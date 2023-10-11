
        #include "TestCodeGeneration.h"

        EFI_STATUS
        EFIAPI
        TestCodeGeneration(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable 
            ) 
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: TestCodeGeneration\n"));

            UINTN Service = 0;
            ReadInput(Input, 1, &Service);

            switch(Service%6)
            {
                case GET_VARIABLE:
                    Status = FuzzGetVariable(Input, SystemTable);
                    break;
                case SET_VARIABLE:
                    Status = FuzzSetVariable(Input, SystemTable);
                    break;
                case GET_NEXT_VARIABLE_NAME:
                    Status = FuzzGetNextVariableName(Input, SystemTable);
                    break;
                case UPDATE_CAPSULE:
                    Status = FuzzUpdateCapsule(Input, SystemTable);
                    break;
                case QUERY_CAPSULE_CAPABILITIES:
                    Status = FuzzQueryCapsuleCapabilities(Input, SystemTable);
                    break;
                case QUERY_VARIABLE_INFO:
                    Status = FuzzQueryVariableInfo(Input, SystemTable);
                    break;
                
            }
            return Status;
        }
        
        EFI_STATUS
        EFIAPI
        FuzzGetVariable(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            )
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: GetVariable\n"));
            const EFI_PEI_READ_ONLY_VARIABLE2_PPI *VariablePpi = AllocatePool(sizeof(const EFI_PEI_READ_ONLY_VARIABLE2_PPI));
            
            
            const CHAR16 *VariableName = AllocatePool(sizeof(const CHAR16));
            
            
            const EFI_GUID *VariableGuid = AllocatePool(sizeof(const EFI_GUID));
            
            
            UINT32 * = AllocatePool(sizeof(UINT32));
            
            
            UINTN *Size = AllocatePool(sizeof(UINTN));
            
            
            void *Buffer = AllocatePool(sizeof(void));
            
            
            

            
            
            return Status;
        }
        
        EFI_STATUS
        EFIAPI
        FuzzSetVariable(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            )
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: SetVariable\n"));
            CHAR16 *Variable = AllocatePool(sizeof(CHAR16));
            
            
            EFI_GUID *Variable = AllocatePool(sizeof(EFI_GUID));
            
            
            UINT32 Variable = 0; 
            
            UINTN Variable = 0; 
            
            void *Variable = AllocatePool(sizeof(void));
            
            
            

            
            Status = SystemTable->RuntimeServices->SetVariable(Variable, Variable, Variable, Variable, Variable);
            
            
            return Status;
        }
        
        EFI_STATUS
        EFIAPI
        FuzzGetNextVariableName(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            )
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: GetNextVariableName\n"));
            UINTN *NameSize = AllocatePool(sizeof(UINTN));
            
            
            CHAR16 *FoundVarName = AllocatePool(sizeof(CHAR16));
            
            
            EFI_GUID *FoundVarGuid = AllocatePool(sizeof(EFI_GUID));
            
            
            

            
            Status = SystemTable->RuntimeServices->GetNextVariableName(&NameSize, FoundVarName, &FoundVarGuid);
            
            
            return Status;
        }
        
        EFI_STATUS
        EFIAPI
        FuzzUpdateCapsule(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            )
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: UpdateCapsule\n"));
            EFI_CAPSULE_HEADER  *CapsuleHeaderArray = AllocatePool(sizeof(EFI_CAPSULE_HEADER ));
            
            
            UINTN CapsuleCount = 0; 
            
            EFI_PHYSICAL_ADDRESS ScatterGatherList = 0; 
            
            

            
            Status = SystemTable->RuntimeServices->UpdateCapsule(CapsuleHeaderArray, CapsuleCount, ScatterGatherList);
            
            
            return Status;
        }
        
        EFI_STATUS
        EFIAPI
        FuzzQueryCapsuleCapabilities(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            )
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: QueryCapsuleCapabilities\n"));
            EFI_CAPSULE_HEADER  *CapsuleHeaderArray = AllocatePool(sizeof(EFI_CAPSULE_HEADER ));
            
            
            UINTN CapsuleCount = 0; 
            
            UINT64 *MaximumCapsuleSize = AllocatePool(sizeof(UINT64));
            
            
            EFI_RESET_TYPE *ResetType = AllocatePool(sizeof(EFI_RESET_TYPE));
            
            
            

            
            Status = SystemTable->RuntimeServices->QueryCapsuleCapabilities(CapsuleHeaderArray, CapsuleCount, MaximumCapsuleSize, ResetType);
            
            
            return Status;
        }
        
        EFI_STATUS
        EFIAPI
        FuzzQueryVariableInfo(
            IN INPUT_BUFFER *Input,
            IN EFI_SYSTEM_TABLE  *SystemTable
            )
        {
            EFI_STATUS Status = EFI_SUCCESS;
            DEBUG ((DEBUG_ERROR, "FUZZING: QueryVariableInfo\n"));
            UINT32 Attributes = 0; 
            
            UINT64 *MaximumVariableStorageSize = AllocatePool(sizeof(UINT64));
            
            
            UINT64 *RemainingVariableStorageSize = AllocatePool(sizeof(UINT64));
            
            
            UINT64 *MaximumVariableSize = AllocatePool(sizeof(UINT64));
            
            
            

            
            Status = SystemTable->RuntimeServices->QueryVariableInfo(Attributes, MaximumVariableStorageSize, RemainingVariableStorageSize, MaximumVariableSize);
            
            
            return Status;
        }
        
        