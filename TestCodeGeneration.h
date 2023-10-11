
        

        #define GET_VARIABLE 0
        #define SET_VARIABLE 1
        #define GET_NEXT_VARIABLE_NAME 2
        #define UPDATE_CAPSULE 3
        #define QUERY_CAPSULE_CAPABILITIES 4
        #define QUERY_VARIABLE_INFO 5
        

        EFI_STATUS
        EFIAPI
        TestCodeGeneration(
            IN INPUT_BUFFER *Input
            );
        
        EFI_STATUS
        EFIAPI
        FuzzGetVariable(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        
        EFI_STATUS
        EFIAPI
        FuzzSetVariable(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        
        EFI_STATUS
        EFIAPI
        FuzzGetNextVariableName(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        
        EFI_STATUS
        EFIAPI
        FuzzUpdateCapsule(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        
        EFI_STATUS
        EFIAPI
        FuzzQueryCapsuleCapabilities(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        
        EFI_STATUS
        EFIAPI
        FuzzQueryVariableInfo(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            );
        
        