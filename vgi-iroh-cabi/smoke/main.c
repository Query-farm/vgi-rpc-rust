#include <vgi_iroh.h>

int main(void) {
    return vgi_iroh_abi_version() == VGI_IROH_ABI_VERSION ? 0 : 1;
}
