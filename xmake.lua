-- Copyright 3bian Limited and CHERIoT Contributors.
-- SPDX-License-Identifier: Apache-2.0

set_project("Ethernet Harness")

sdkdir = "third_party/cheriot_rtos/sdk"
set_toolchains("cheriot-clang")

includes("third_party/cheriot_rtos/sdk",
         "third_party/cheriot_rtos/sdk/lib")

option("board")
    set_default("sonata")

compartment("entry_point")
    set_default(false)
    add_deps("freestanding",
             "debug")
    add_includedirs("include")
    add_files("src/main.cc")

firmware("ethernet-harness")
    add_deps("entry_point")
    on_load(function(target)
        target:values_set("board", "$(board)")
        target:values_set("threads", {
            {
                compartment = "entry_point",
                priority = 1,
                entry_point = "init",
                stack_size = 0x1000,
                trusted_stack_frames = 5
            }
        }, {expand = false})
    end)
