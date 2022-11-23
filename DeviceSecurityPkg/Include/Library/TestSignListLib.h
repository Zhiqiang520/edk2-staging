#include <Uefi.h>
#include <Guid/ImageAuthentication.h>
#include <Stub/SpdmLibStub.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

VOID
Traverse_SignatureList (
  IN EFI_SIGNATURE_LIST  *SignatureList,
  IN UINTN               SignatureListSize
  );