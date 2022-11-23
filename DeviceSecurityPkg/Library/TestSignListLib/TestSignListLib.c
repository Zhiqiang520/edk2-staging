#include <Library/TestSignListLib.h>

VOID
Traverse_SignatureList (
  IN EFI_SIGNATURE_LIST  *SignatureList,
  IN UINTN               SignatureListSize
  )
{
  VOID                 *SpdmContext;
  UINTN                SpdmContextSize;
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
    while ((DbSize > 0) && (SignatureListSize >= DbList->SignatureListSize)) {
      if (!CompareGuid (&DbList->SignatureType, &gEfiCertX509Guid)) {
        DbSize -= DbList->SignatureListSize;
        DbList  = (EFI_SIGNATURE_LIST *)((UINT8 *)DbList + DbList->SignatureListSize);
        continue;
      }
      ASSERT (DbList->SignatureHeaderSize == 0);
      SiglistHeaderSize = sizeof (EFI_SIGNATURE_LIST) + DbList->SignatureHeaderSize;
      Cert = (EFI_SIGNATURE_DATA *)((UINT8 *)DbList + SiglistHeaderSize);
      CertCount = (DbList->SignatureListSize - SiglistHeaderSize) / DbList->SignatureSize;

      for (Index = 0; Index < CertCount; Index ++) {
        Data = Cert->SignatureData;
        DataSize = DbList->SignatureSize - sizeof (EFI_GUID);

        ZeroMem (&Parameter, sizeof (Parameter));
        Parameter.location = SpdmDataLocationLocal;
        SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCert, &Parameter, Data, DataSize);

        Cert = (EFI_SIGNATURE_DATA *)((UINT8 *)Cert + DbList->SignatureSize);
      }

      DbSize -= DbList->SignatureListSize;
      DbList  = (EFI_SIGNATURE_LIST *)((UINT8 *)DbList + DbList->SignatureListSize);
    }
  }
}