/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "KeyUtil.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <thread>

#include <fcntl.h>
#include <linux/blk-crypto.h>
#include <linux/fscrypt.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>

#include <android-base/file.h>
#include <android-base/logging.h>

#include "KeyStorage.h"
#include "Keystore.h"
#include "RandUtils.h"
#include "Utils.h"
#include "VoldUtil.h"

static const int32_t KM_TAG_FBE_ICE = static_cast<int32_t>(7 << 28) | 16201;

namespace android {
namespace vold {

using android::fscrypt::EncryptionOptions;
using android::fscrypt::EncryptionPolicy;
using android::fscrypt::KeyType;

// This must be acquired before calling fscrypt ioctls that operate on keys.
// This prevents race conditions between evicting and reinstalling keys.
static std::mutex fscrypt_keyring_mutex;

const KeyGeneration neverGen() {
    return KeyGeneration{0, false, KeyType::kRaw};
}

static bool generateRawStorageKey(size_t size, KeyBuffer* key) {
    *key = KeyBuffer(size);
    if (ReadRandomBytes(key->size(), key->data()) != 0) {
        // TODO status_t plays badly with PLOG, fix it.
        LOG(ERROR) << "Random read failed";
        return false;
    }
    return true;
}

// Generate wrapped storage key using keystore. Uses STORAGE_KEY tag in keystore.
static bool generateV0WrappedStorageKey(KeyBuffer* key) {
    Keystore keystore;
    if (!keystore) return false;
    std::string key_temp;
    auto paramBuilder = km::AuthorizationSetBuilder().AesEncryptionKey(AES_KEY_BYTES * 8);
    paramBuilder.Authorization(km::TAG_STORAGE_KEY);

    km::KeyParameter param1;
    param1.tag = (km::Tag) (KM_TAG_FBE_ICE);
    param1.value = km::KeyParameterValue::make<km::KeyParameterValue::boolValue>(true);
    paramBuilder.push_back(param1);

    if (!keystore.generateKey(paramBuilder, &key_temp)) return false;
    *key = KeyBuffer(key_temp.size());
    memcpy(reinterpret_cast<void*>(key->data()), key_temp.c_str(), key->size());
    return true;
}

// This matches the limit used by the kernel internally as of v6.17.  It is enough for all known
// wrapped key implementatations.  It can be increased in the future if needed.
constexpr size_t BLK_CRYPTO_MAX_HW_WRAPPED_KEY_SIZE = 128;

static bool generateWrappedStorageKey(KeyBuffer* key) {
    // BLKCRYPTOGENERATEKEY requires a block device.  For now, just always use the "main" userdata
    // block device, even if the userdata filesystem has multiple block devices or the key is being
    // generated for adoptable storage instead of internal storage.  This provides parity with the
    // original KeyMint based solution, which didn't differentiate between block devices.  All known
    // wrapped key implementations used on Android devices have compatible keys between block
    // devices, and they typically don't support adoptable storage anyway.  This could be changed
    // later to pass in the correct volume's block device, but for now this is all that's needed.
    std::string blk_device = GetUserDataBlockDevicePath();
    if (blk_device.empty()) {
        LOG(ERROR) << "Failed to get path to userdata block device";
        return false;
    }
    android::base::unique_fd fd(open(blk_device.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << blk_device << " to generate key";
        return false;
    }

    key->resize(BLK_CRYPTO_MAX_HW_WRAPPED_KEY_SIZE);
    struct blk_crypto_generate_key_arg arg = {
            .lt_key_ptr = (uintptr_t)key->data(),
            .lt_key_size = key->size(),
    };

    if (ioctl(fd, BLKCRYPTOGENERATEKEY, &arg) != 0) {
        PLOG(ERROR) << "BLKCRYPTOGENERATEKEY failed on " << blk_device;
        return false;
    }
    key->resize(arg.lt_key_size);
    return true;
}

bool generateStorageKey(const KeyGeneration& gen, KeyBuffer* key) {
    if (!gen.allow_gen) {
        LOG(ERROR) << "Generating storage key not allowed";
        return false;
    }
    switch (gen.key_type) {
        case KeyType::kRaw:
            LOG(DEBUG) << "Generating raw storage key";
            return generateRawStorageKey(gen.keysize, key);
        case KeyType::kHwWrappedV0:
            if (gen.keysize != FSCRYPT_MAX_KEY_SIZE) {
                LOG(ERROR) << "Cannot generate a wrapped key " << gen.keysize << " bytes long";
                return false;
            }
            LOG(DEBUG) << "Generating v0 wrapped storage key";
            return generateV0WrappedStorageKey(key);
        case KeyType::kHwWrapped:
            if (gen.keysize != FSCRYPT_MAX_KEY_SIZE) {
                LOG(ERROR) << "Cannot generate a wrapped key " << gen.keysize << " bytes long";
                return false;
            }
            LOG(DEBUG) << "Generating wrapped storage key";
            return generateWrappedStorageKey(key);
    }
    LOG(ERROR) << "Unknown KeyType";
    return false;
}

static bool prepareV0WrappedKeyForUse(const KeyBuffer& lt_key, KeyBuffer* kernel_key) {
    Keystore keystore;
    if (!keystore) return false;
    std::string key_temp;

    if (!keystore.exportKey(lt_key, &key_temp)) return false;
    *kernel_key = KeyBuffer(key_temp.size());
    memcpy(reinterpret_cast<void*>(kernel_key->data()), key_temp.c_str(), kernel_key->size());
    return true;
}

static bool prepareWrappedKeyForUse(const KeyBuffer& lt_key, KeyBuffer* kernel_key) {
    // As with generateWrappedStorageKey(), for now we always execute the ioctl on the main userdata
    // block device and assume the keys are compatible across block devices.
    std::string blk_device = GetUserDataBlockDevicePath();
    if (blk_device.empty()) {
        LOG(ERROR) << "Failed to get path to userdata block device";
        return false;
    }
    android::base::unique_fd fd(open(blk_device.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << blk_device << " to prepare key";
        return false;
    }

    kernel_key->resize(BLK_CRYPTO_MAX_HW_WRAPPED_KEY_SIZE);
    struct blk_crypto_prepare_key_arg arg = {
            .lt_key_ptr = (uintptr_t)lt_key.data(),
            .lt_key_size = lt_key.size(),
            .eph_key_ptr = (uintptr_t)kernel_key->data(),
            .eph_key_size = kernel_key->size(),
    };

    if (ioctl(fd, BLKCRYPTOPREPAREKEY, &arg) != 0) {
        PLOG(ERROR) << "BLKCRYPTOPREPAREKEY failed on " << blk_device;
        return false;
    }
    kernel_key->resize(arg.eph_key_size);
    return true;
}

bool prepareKeyForUse(const KeyBuffer& lt_key, KeyType type, KeyBuffer* kernel_key) {
    switch (type) {
        case KeyType::kRaw:
            *kernel_key = lt_key;
            return true;
        case KeyType::kHwWrappedV0:
            if (!prepareV0WrappedKeyForUse(lt_key, kernel_key)) {
                LOG(ERROR) << "Failed to get ephemeral wrapped key";
                return false;
            }
            return true;
        case KeyType::kHwWrapped:
            return prepareWrappedKeyForUse(lt_key, kernel_key);
    }
    LOG(ERROR) << "Unknown KeyType";
    return false;
}

// Get raw keyref - used to make keyname and to pass to ioctl
static std::string generateKeyRef(const uint8_t* key, int length) {
    SHA512_CTX c;

    SHA512_Init(&c);
    SHA512_Update(&c, key, length);
    unsigned char key_ref1[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref1, &c);

    SHA512_Init(&c);
    SHA512_Update(&c, key_ref1, SHA512_DIGEST_LENGTH);
    unsigned char key_ref2[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref2, &c);

    static_assert(FSCRYPT_KEY_DESCRIPTOR_SIZE <= SHA512_DIGEST_LENGTH,
                  "Hash too short for descriptor");
    return std::string((char*)key_ref2, FSCRYPT_KEY_DESCRIPTOR_SIZE);
}

static std::string keyrefstring(const std::string& raw_ref) {
    std::ostringstream o;
    for (unsigned char i : raw_ref) {
        o << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }
    return o.str();
}

// Build a struct fscrypt_key_specifier for use in the key management ioctls.
static bool buildKeySpecifier(fscrypt_key_specifier* spec, const EncryptionPolicy& policy) {
    switch (policy.options.version) {
        case 1:
            if (policy.key_raw_ref.size() != FSCRYPT_KEY_DESCRIPTOR_SIZE) {
                LOG(ERROR) << "Invalid key specifier size for v1 encryption policy: "
                           << policy.key_raw_ref.size();
                return false;
            }
            spec->type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
            memcpy(spec->u.descriptor, policy.key_raw_ref.c_str(), FSCRYPT_KEY_DESCRIPTOR_SIZE);
            return true;
        case 2:
            if (policy.key_raw_ref.size() != FSCRYPT_KEY_IDENTIFIER_SIZE) {
                LOG(ERROR) << "Invalid key specifier size for v2 encryption policy: "
                           << policy.key_raw_ref.size();
                return false;
            }
            spec->type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
            memcpy(spec->u.identifier, policy.key_raw_ref.c_str(), FSCRYPT_KEY_IDENTIFIER_SIZE);
            return true;
        default:
            LOG(ERROR) << "Invalid encryption policy version: " << policy.options.version;
            return false;
    }
}

bool installKey(const std::string& mountpoint, const EncryptionOptions& options,
                const KeyBuffer& key, EncryptionPolicy* policy) {
    const std::lock_guard<std::mutex> lock(fscrypt_keyring_mutex);
    policy->options = options;
    // Put the fscrypt_add_key_arg in an automatically-zeroing buffer, since we
    // have to copy the raw key into it.
    KeyBuffer arg_buf(sizeof(struct fscrypt_add_key_arg) + key.size(), 0);
    struct fscrypt_add_key_arg* arg = (struct fscrypt_add_key_arg*)arg_buf.data();

    // Initialize the "key specifier", which is like a name for the key.
    switch (options.version) {
        case 1:
            // A key for a v1 policy is specified by an arbitrary 8-byte
            // "descriptor", which must be provided by userspace.  We use the
            // first 8 bytes from the double SHA-512 of the key itself.
            if (options.key_type == KeyType::kHwWrappedV0) {
                /* When wrapped key is supported, only the first 32 bytes are
                   the same per boot. The second 32 bytes can change as the ephemeral
                   key is different. */
                policy->key_raw_ref = generateKeyRef((const uint8_t*)key.data(), key.size()/2);
            } else {
                policy->key_raw_ref = generateKeyRef((const uint8_t*)key.data(), key.size());
            }
            if (!buildKeySpecifier(&arg->key_spec, *policy)) {
                return false;
            }
            break;
        case 2:
            // A key for a v2 policy is specified by an 16-byte "identifier",
            // which is a cryptographic hash of the key itself which the kernel
            // computes and returns.  Any user-provided value is ignored; we
            // just need to set the specifier type to indicate that we're adding
            // this type of key.
            arg->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
            break;
        default:
            LOG(ERROR) << "Invalid encryption policy version: " << options.version;
            return false;
    }

    switch (options.key_type) {
        case KeyType::kRaw:
            break;
        case KeyType::kHwWrappedV0:
            // With the "wrappedkey_v0" option, continue using the legacy Android-specific flag for
            // backwards compatibility.  This field and flag were not reserved upstream, so their
            // location and names were chosen to avoid colliding with future upstream changes.
            //
            // Note that the legacy and upstream flags select slightly different on-disk formats.
            // So we can't just use the upstream one unconditionally.
            arg->__flags |= __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED;
            break;
        case KeyType::kHwWrapped:
            // With the "wrappedkey" option, use the upstream flag.
            arg->flags |= FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED;
            break;
    }
    // Provide the raw key.
    arg->raw_size = key.size();
    memcpy(arg->raw, key.data(), key.size());

    android::base::unique_fd fd(open(mountpoint.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << mountpoint << " to install key";
        return false;
    }

    if (ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, arg) != 0) {
        PLOG(ERROR) << "Failed to install fscrypt key to " << mountpoint;
        return false;
    }

    if (arg->key_spec.type == FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER) {
        // Retrieve the key identifier that the kernel computed.
        policy->key_raw_ref =
                std::string((char*)arg->key_spec.u.identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);
    }
    LOG(DEBUG) << "Installed fscrypt key with ref " << keyrefstring(policy->key_raw_ref) << " to "
               << mountpoint;
    return true;
}

static void waitForBusyFiles(const struct fscrypt_key_specifier key_spec, const std::string ref,
                             const std::string mountpoint) {
    android::base::unique_fd fd(open(mountpoint.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << mountpoint << " to evict key";
        return;
    }

    std::chrono::milliseconds wait_time(3200);
    std::chrono::milliseconds total_wait_time(0);
    while (wait_time <= std::chrono::milliseconds(51200)) {
        total_wait_time += wait_time;
        std::this_thread::sleep_for(wait_time);

        const std::lock_guard<std::mutex> lock(fscrypt_keyring_mutex);

        struct fscrypt_get_key_status_arg get_arg;
        memset(&get_arg, 0, sizeof(get_arg));
        get_arg.key_spec = key_spec;

        if (ioctl(fd, FS_IOC_GET_ENCRYPTION_KEY_STATUS, &get_arg) != 0) {
            PLOG(ERROR) << "Failed to get status for fscrypt key with ref " << ref << " from "
                        << mountpoint;
            return;
        }
        if (get_arg.status != FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED) {
            LOG(DEBUG) << "Key status changed, cancelling busy file cleanup for key with ref "
                       << ref << ".";
            return;
        }

        struct fscrypt_remove_key_arg remove_arg;
        memset(&remove_arg, 0, sizeof(remove_arg));
        remove_arg.key_spec = key_spec;

        if (ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY, &remove_arg) != 0) {
            PLOG(ERROR) << "Failed to clean up busy files for fscrypt key with ref " << ref
                        << " from " << mountpoint;
            return;
        }
        if (remove_arg.removal_status_flags & FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS) {
            // Should never happen because keys are only added/removed as root.
            LOG(ERROR) << "Unexpected case: key with ref " << ref
                       << " is still added by other users!";
        } else if (!(remove_arg.removal_status_flags &
                     FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY)) {
            LOG(INFO) << "Successfully cleaned up busy files for key with ref " << ref
                      << ".  After waiting " << total_wait_time.count() << "ms.";
            return;
        }
        LOG(WARNING) << "Files still open after waiting " << total_wait_time.count()
                     << "ms.  Key with ref " << ref << " still has unlocked files!";
        wait_time *= 2;
    }
    LOG(ERROR) << "Waiting for files to close never completed.  Files using key with ref " << ref
               << " were not locked!";
}

bool evictKey(const std::string& mountpoint, const EncryptionPolicy& policy) {
    const std::lock_guard<std::mutex> lock(fscrypt_keyring_mutex);

    android::base::unique_fd fd(open(mountpoint.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Failed to open " << mountpoint << " to evict key";
        return false;
    }

    struct fscrypt_remove_key_arg arg;
    memset(&arg, 0, sizeof(arg));

    if (!buildKeySpecifier(&arg.key_spec, policy)) {
        return false;
    }

    std::string ref = keyrefstring(policy.key_raw_ref);

    if (ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY, &arg) != 0) {
        PLOG(ERROR) << "Failed to evict fscrypt key with ref " << ref << " from " << mountpoint;
        return false;
    }

    LOG(DEBUG) << "Evicted fscrypt key with ref " << ref << " from " << mountpoint;
    if (arg.removal_status_flags & FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS) {
        // Should never happen because keys are only added/removed as root.
        LOG(ERROR) << "Unexpected case: key with ref " << ref << " is still added by other users!";
    } else if (arg.removal_status_flags & FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY) {
        LOG(WARNING)
                << "Files still open after removing key with ref " << ref
                << ".  These files were not locked!  Punting busy file clean up to worker thread.";
        // Processes are killed asynchronously in ActivityManagerService due to performance issues
        // with synchronous kills.  If there were busy files they will probably be killed soon. Wait
        // for them asynchronously.
        std::thread busyFilesThread(waitForBusyFiles, arg.key_spec, ref, mountpoint);
        busyFilesThread.detach();
    }
    return true;
}

bool retrieveOrGenerateKey(const std::string& key_path, const std::string& tmp_path,
                           const KeyAuthentication& key_authentication, const KeyGeneration& gen,
                           KeyBuffer* key) {
    if (pathExists(key_path)) {
        LOG(DEBUG) << "Key exists, using: " << key_path;
        if (!retrieveKey(key_path, key_authentication, key)) return false;
    } else {
        if (!gen.allow_gen) {
            LOG(ERROR) << "No key found in " << key_path;
            return false;
        }
        LOG(INFO) << "Creating new key in " << key_path;
        if (!generateStorageKey(gen, key)) return false;
        if (!storeKeyAtomically(key_path, tmp_path, key_authentication, *key)) return false;
    }
    return true;
}

}  // namespace vold
}  // namespace android
