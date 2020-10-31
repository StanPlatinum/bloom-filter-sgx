#include <stdio.h>

#include <iostream>
#include <fstream>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t prev_global_eid = 0;
sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t after_global_eid = 0;

int ptr;
//alloc buffer
size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);

// OCall implementations
void ocall_print(const char *str)
{
    printf("%s", str);
}

void ocall_print_file(const char *str, const char *file, int append) {
    std::ofstream stream;

    stream.open(std::string(file), append == 0 ? std::ofstream::out : std::ofstream::app);

    std::cout << "Writing to file " << std::string(file) << std::endl;
    if (!stream)
        std::cout << "Opening file failed" << std::endl;
    // use operator<< for clarity
    stream << std::string(str) << std::endl;
    // test if write was succesful - not *really* necessary
    if (!stream)
        std::cout << "Write failed" << std::endl;

    stream.close();
}

void send2outside(uint8_t *ocall_sealed_data, size_t ocall_sealed_size)
{
    unsigned char *sealed_data_array = (unsigned char *)ocall_sealed_data;
    for (int i = 0; i < ocall_sealed_size; i++)
    {
        printf("%u,", sealed_data_array[i]);
    }

    sealed_size = ocall_sealed_size;
    if (sealed_size != ocall_sealed_size)   printf("something wrong\n");
    memcpy(sealed_data, ocall_sealed_data, ocall_sealed_size);
    
    printf("\ntest memcpy\n");
    sealed_data_array = (unsigned char *)sealed_data;
    for (int i = 0; i < sealed_size; i++)
    {
        printf("%u,", sealed_data_array[i]);
    }
}

int main(int argc, char const *argv[])
{

    //create previous enclave
    if (initialize_enclave(&prev_global_eid, "enclave.token", "enclave.signed.so") < 0)
    {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    printf("prev_global_eid: %ld\n", prev_global_eid);

    //generate the random number from prev_enclave

    sgx_status_t app_status;

    app_status = generate_random_number(prev_global_eid, &ptr);
    if (app_status != SGX_SUCCESS)
    {
        std::cout << "noob" << std::endl;
    }
    printf("Random number: %d\n", ptr);

    //we seal the data in previous enclave

    // Seal the number
    sgx_status_t ecall_status;
    app_status = seal(prev_global_eid, &ecall_status,
                      (uint8_t *)&ptr, sizeof(ptr),
                      (sgx_sealed_data_t *)sealed_data, sealed_size);

    if (!is_ecall_successful(app_status, "Sealing failed :(", ecall_status))
    {
        return 1;
    }
    //-------------------------------------

    //now

    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0)
    {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    printf("global_eid: %ld\n", global_eid);

    //unseal inside
    // app_status = unseal_inside(prev_global_eid, &ecall_status,
    app_status = unseal_inside(global_eid, &ecall_status,
                               (sgx_sealed_data_t *)sealed_data, sealed_size);

    if (!is_ecall_successful(app_status, "Unsealing failed :(", ecall_status))
    {
        return 1;
    }

    //seal, to the outside
    sgx_status_t compute_status = compute_and_seal(global_eid);
    if (!is_ecall_successful(compute_status, "Unsealing failed :("))
    {
        return 1;
    }
    
    //not seal, to the outside in a sam file
    sgx_status_t output_status = compute_and_output(global_eid);
    if (!is_ecall_successful(compute_status, "output failed :("))
    {
        return 1;
    }
    
    //-------------------------------------
    if (initialize_enclave(&after_global_eid, "enclave.token", "enclave.signed.so") < 0)
    {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    printf("after_global_eid: %ld\n", after_global_eid);

    //unseal again
    int unsealed_after;

    printf("sealed_size: %d\n", sealed_size);

    sgx_status_t status = unseal(after_global_eid, &ecall_status,
                    (sgx_sealed_data_t *)sealed_data, sealed_size,
                    (uint8_t *)&unsealed_after, sizeof(unsealed_after));
    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status))
    {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back " << unsealed_after << std::endl;

    //-------------------------------------

	char *message = "Hello, crypto enclave!";
	printf("Original message: %s\n", message);

	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(message)); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

	printf("Encrypting...\n");
	status = encryptMessage(after_global_eid, message, strlen(message), encMessage, encMessageLen);
	encMessage[encMessageLen] = '\0';
	printf("Encrypted message: %s\n", encMessage);
	
	// The decrypted message will contain the same message as the original one.
	size_t decMessageLen = strlen(message);
	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));

	printf("Decrypting...\n");
	status = decryptMessage(after_global_eid,encMessage,encMessageLen,decMessage,decMessageLen);
	decMessage[decMessageLen] = '\0';
	printf("Decrypted message: %s", decMessage);

    return 0;
}