#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "Enclave_t.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}

int data;

//enclave 1
int generate_random_number()
{
    //printf("Processing number generation...");
    //not random
    return 42;
}

//enclave 2
//data
int unsealed_data;
uint8_t *plaintext = (uint8_t *)&unsealed_data;
uint32_t plaintext_len = sizeof(unsealed_data);

sgx_status_t unseal_inside(sgx_sealed_data_t *sealed_data, size_t sealed_size)
{
    // unsigned char *sealed_data_array = (unsigned char *)sealed_data;
    // for (int i = 0; i < sealed_size; i++)
    // {
    //     printf("%u,", sealed_data_array[i]);
    // }
    sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t *)plaintext, &plaintext_len);
    printf("unsealed inside: %d\n", unsealed_data);
    return status;
}

sgx_status_t seal_inside(uint8_t *plaintext, size_t plaintext_len, sgx_sealed_data_t *sealed_data, size_t sealed_size)
{
    sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
    return status;
}

void compute_and_seal(void)
{
    data = unsealed_data;
    data++;

    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(data);
    uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);

    sgx_status_t status = seal_inside((uint8_t *)&data, sizeof(data), (sgx_sealed_data_t *)sealed_data, sealed_size);
    send2outside(sealed_data, sealed_size);
}

void compute_and_output(void)
{
    data = unsealed_data;
    data++;
    char output_data[9];
    snprintf(output_data, 8, "%d", data);
    const char *file_name = "test.sam";
    ocall_print_file((const char *)&output_data, file_name, 0);
}
