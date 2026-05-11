# process-hollower
It's VERY important for the source file to be compatible with the application we're trying to load it in, so it must meet a few requirements:
Application architecture isn't even a question here, anyone can realize that you can't load a 32 bit app into a 64 bit app.
For the actual requirements:
1. the subsystem of the source file should be set to `windows`

   `Linker -> System -> Subsystem -> Windows`
3. the compiler should use the static version of the run-time library to remove dependence
to the Visual C++ runtime DLL, to do this, just use the /MT or /MTd (for debug) compiler options

    `Properties -> C/C++ -> Code Generation -> Runtime library -> Multi-Threaded (/MT)`

5. either the preferred base address (assuming it has one) of the source image must match
  that of the destination image, or the source must contain a relocation table and the
  image needs to be rebased to the address of the destination. For compatibility reasons
  the rebasing route is preferred. The /DYNAMICBASE or /FIXED:NO linker options can
  be used to generate a relocation table.

     `Linker -> Advanced -> Randomized Base Address -> Yes (/DYNAMICBASE)`
  
     `Linker -> Advanced -> Randomized Base Address -> Fixed Base Address -> No (/FIXED:NO)`
   
in-depth explanation of process hollowing is explained very well by my boy john (PDF attached)

NOTE: this application is built in x64 and the explanation is for x86
