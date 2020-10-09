void ecall_load_bf(unsigned char *data, long char_len, long bf_len)
{
    printf("debugging ecall_load_bf\n");
    for (int i = 0; i < bf_len; i++)
        printf("Buffer in enclave: %c\n", data[i]);
    free(data);
}

int main()
{
    printf("test 2\n");
    unsigned char *data = (unsigned char *)malloc(10);
    long char_len = 10;
    long bf_len = 10;
    memset(data, '*', 10);
    for (int i = 0; i < bf_len; i++)
        printf("Buffer after memset: %c\n", data[i]);

    ecall_load_bf(data, char_len, bf_len);
    return 0;
}
