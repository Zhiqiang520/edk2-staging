#include <Library/TestSignListLib.h>

VOID
Traverse_SignatureList (
  IN EFI_SIGNATURE_LIST  *SignatureList,
  IN UINTN               SignatureListSize
  )
{
  VOID                 *SpdmContext;
  UINTN                SpdmContextSize;
  SPDM_RETURN          SpdmReturn;
  EFI_SIGNATURE_LIST   *DbList;
  EFI_SIGNATURE_DATA   *Cert;
  UINTN                CertCount;
  UINTN                Index;
  UINTN                SiglistHeaderSize;
  UINTN                DbSize;
  VOID                 *Data;
  UINTN                DataSize;
  SPDM_DATA_PARAMETER  Parameter;
  
  SpdmContextSize = SpdmGetContextSize ();
  SpdmContext     = AllocateZeroPool (SpdmContextSize);

  if (SignatureList != NULL) {
    DbList = SignatureList;
    DbSize = SignatureListSize;
    printf("SignatureListSize out of while- 0x%x\n", SignatureListSize);
    printf("DbList->SignatureListSize out of while- 0x%x\n", DbList->SignatureListSize);
    while ((DbSize > 0) && (SignatureListSize >= DbList->SignatureListSize)) {
      printf("DbSize at begin of while- 0x%x\n", DbSize);
      printf("DbList->SignatureListSize at begin of while- 0x%x\n", DbList->SignatureListSize);
      printf("DbList->SignatureSize at begin of while- 0x%x\n", DbList->SignatureSize);
      if (DbList->SignatureListSize == 0) {
        break;
      }
      if ((!CompareGuid (&DbList->SignatureType, &gEfiCertX509Guid))
           || (DbList->SignatureHeaderSize != 0)
           || (DbList->SignatureSize < sizeof (EFI_SIGNATURE_DATA))) {
        printf("DbSize at begin of CompareGuid block- 0x%x\n", DbSize);
        printf("DbList->SignatureListSize at begin of CompareGuid block- 0x%x\n", DbList->SignatureListSize);
        DbSize -= DbList->SignatureListSize;
        DbList  = (EFI_SIGNATURE_LIST *)((UINT8 *)DbList + DbList->SignatureListSize);
        printf("DbSize at end of CompareGuid block- 0x%x\n", DbSize);
        printf("DbList->SignatureListSize at end of CompareGuid block- 0x%x\n", DbList->SignatureListSize);
        continue;
      }

      SiglistHeaderSize = sizeof (EFI_SIGNATURE_LIST) + DbList->SignatureHeaderSize;
      Cert = (EFI_SIGNATURE_DATA *)((UINT8 *)DbList + SiglistHeaderSize);
      CertCount = (DbList->SignatureListSize - SiglistHeaderSize) / DbList->SignatureSize;
      printf("CertCount in while block- 0x%x\n", CertCount);

      for (Index = 0; Index < CertCount; Index ++) {
        printf("Index in for block- 0x%x\n", Index);
        Data = Cert->SignatureData;
        DataSize = DbList->SignatureSize - sizeof (EFI_GUID);

        ZeroMem (&Parameter, sizeof (Parameter));
        Parameter.location = SpdmDataLocationLocal;
        SpdmReturn = SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCert, &Parameter, Data, DataSize);
        if (LIBSPDM_STATUS_IS_ERROR(SpdmReturn)) {
          goto Error;
        }
        Cert = (EFI_SIGNATURE_DATA *)((UINT8 *)Cert + DbList->SignatureSize);
      }

      DbSize -= DbList->SignatureListSize;
      DbList  = (EFI_SIGNATURE_LIST *)((UINT8 *)DbList + DbList->SignatureListSize);
      printf("DbSize at end of while- 0x%x\n", DbSize);
      printf("DbList->SignatureListSize at end of while- 0x%x\n", DbList->SignatureListSize);
      printf("DbList->SignatureSize at end of while- 0x%x\n", DbList->SignatureSize);
    }
  }
Error:
  FreePool (SpdmContext);
}