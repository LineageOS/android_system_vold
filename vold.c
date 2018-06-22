/*
 * Copyright (C) 2015 The CyanogenMod Project
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "vold.h"
#include "minivold_cmds.h"

int main(int argc, char **argv) {
    // Handle alternative invocations
    char* command = argv[0];
    char* stripped = strrchr(argv[0], '/');
    if (stripped)
        command = stripped + 1;
    if (strcmp(command, "minivold") != 0) {
        struct minivold_cmd cmd = get_command(command);
        if (cmd.name)
            return cmd.main_func(argc, argv);
        fprintf(stderr, "Unhandled command %s\n", command);
        return 1;
    }

    return vold_main(argc, argv);
}
