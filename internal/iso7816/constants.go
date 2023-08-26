package iso7816

type Instruction byte

const (
	InsDeactivateFile                 Instruction = 0x04 // Part 9
	InsEraseRecord                    Instruction = 0x0c // Section 7.3.8
	InsEraseBinary                    Instruction = 0x0e // Section 7.2.7
	InsEraseBinaryEven                Instruction = 0x0f // Section 7.2.7
	InsPerformSCQLOperation           Instruction = 0x10 // Part 7
	InsPerformTransactionOperation    Instruction = 0x12 // Part 7
	InsPerformUserOperation           Instruction = 0x14 // Part 7
	InsVerify                         Instruction = 0x20 // Section 7.5.6
	InsVerifyOdd                      Instruction = 0x21 // Section 7.5.6
	InsManageSecurityEnvironment      Instruction = 0x22 // Section 7.5.11
	InsChangeReferenceData            Instruction = 0x24 // Section 7.5.7
	InsDisableVerificationRequirement Instruction = 0x26 // Section 7.5.9
	InsEnableVerificationRequirement  Instruction = 0x28 // Section 7.5.8
	InsPerformSecurityOperation       Instruction = 0x2a // Part 8
	InsResetRetryCounter              Instruction = 0x2c // Section 7.5.10
	InsActivateFile                   Instruction = 0x44 // Part 9
	InsGenerateAsymmetricKeyPair      Instruction = 0x46 // Part 8
	InsManageChannel                  Instruction = 0x70 // Section 7.1.2
	InsExternalOrMutualAuthenticate   Instruction = 0x82 // Section 7.5.4
	InsGetChallenge                   Instruction = 0x84 // Section 7.5.3
	InsGeneralAuthenticate            Instruction = 0x87 // Section 7.5.5
	InsInternalAuthenticate           Instruction = 0x88 // Section 7.5.2
	InsSearchBinary                   Instruction = 0xa0 // Section 7.2.6
	InsSearchBinaryOdd                Instruction = 0xa1 // Section 7.2.6
	InsSearchRecord                   Instruction = 0xa2 // Section 7.3.7
	InsSelect                         Instruction = 0xa4 // Section 7.1.1
	InsReadBinary                     Instruction = 0xb0 // Section 7.2.3
	InsReadBinaryOdd                  Instruction = 0xb1 // Section 7.2.3
	InsReadRecord                     Instruction = 0xb3 // Section 7.3.3
	InsGetResponse                    Instruction = 0xc0 // Section 7.6.1
	InsEnvelope                       Instruction = 0xc2 // Section 7.6.2
	InsEnvelopeOdd                    Instruction = 0xc3 // Section 7.6.2
	InsGetData                        Instruction = 0xca // Section 7.4.2
	InsGetDataOdd                     Instruction = 0xcb // Section 7.4.2
	InsWriteBinary                    Instruction = 0xd0 // Section 7.2.6
	InsWriteBinaryOdd                 Instruction = 0xd1 // Section 7.2.6
	InsWriteRecord                    Instruction = 0xd2 // Section 7.3.4
	InsUpdateBinary                   Instruction = 0xd7 // Section 7.2.5
	InsPutData                        Instruction = 0xda // Section 7.4.3
	InsPutDataOdd                     Instruction = 0xdb // Section 7.4.3
	InsUpdateRecord                   Instruction = 0xdc // Section 7.3.5
	InsUpdateRecordOdd                Instruction = 0xdd // Section 7.3.5
	InsCreateFile                     Instruction = 0xe0 // Part 9
	InsAppendRecord                   Instruction = 0xe2 // Section 7.3.6
	InsDeleteFile                     Instruction = 0xe4 // Part 9
	InsTerminateDF                    Instruction = 0xe6 // Part 9
	InsTerminateEF                    Instruction = 0xe8 // Part 9
	InsTerminateCardUsage             Instruction = 0xfe // Part 9
)
