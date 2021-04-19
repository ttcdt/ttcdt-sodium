/*

    ttcdt-sodium - Tool for asymmetric encryption of files using libsodium

    ttcdt <dev@triptico.com>

    This software is released into the public domain.

*/

#include <stdio.h>
#include <string.h>

#include <sodium.h>

#define VERSION "1.06"


int read_key_file(unsigned char *p, int size, char *fn)
/* reads a one-line base64 text file into buffer */
{
    int ret = 0;
    FILE *f = NULL;

    if ((f = fopen(fn, "r")) != NULL) {
        char base64[4096];

        if (fgets(base64, sizeof(base64) - 1, f)) {
            int l = strlen(base64);

            if (base64[l - 1] == '\n') {
                l--;
                base64[l] = '\0';
            }

            if (sodium_base642bin(p, size, base64, l, "", NULL, NULL,
                                  sodium_base64_VARIANT_ORIGINAL) != 0) {
                ret = 2;
                fprintf(stderr, "ERROR: (%d) sodium_base642bin() in '%s'\n", ret, fn);
            }
        }
        else {
            ret = 2;
            fprintf(stderr, "ERROR: (%d) empty key in '%s'\n", ret, fn);
        }

        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) cannot open '%s'\n", ret, fn);
    }

    return ret;
}


int write_key_file(unsigned char *p, int size, char *fn)
/* writes a buffer as a one-line base64 text file */
{
    int ret = 0;
    FILE *f;

    if ((f = fopen(fn, "w")) != NULL) {
        char base64[4096];

        /* convert buffer to base64 */
        sodium_bin2base64(base64, sizeof(base64), p, size,
                          sodium_base64_VARIANT_ORIGINAL);

        fprintf(f, "%s\n", base64);
        fclose(f);
    }
    else {
        ret = 3;
        fprintf(stderr, "ERROR: (%d) cannot create '%s'\n", ret, fn);
    }

    return ret;
}


int generate_keys(char *pk_fn, char *sk_fn)
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    /* create a new keypair */
    crypto_box_keypair(pk, sk);

    /* write the secret and public keys */
    return write_key_file(sk, sizeof(sk), sk_fn) +
           write_key_file(pk, sizeof(pk), pk_fn);
}


int rebuild_public_key(char *pk_fn, char *sk_fn)
{
    int ret = 0;
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    /* read the secret key */
    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) == 0) {
        /* recompute public key */
        crypto_scalarmult_base(pk, sk);

        /* write it */
        ret = write_key_file(pk, sizeof(pk), pk_fn);
    }

    return ret;
}

#define BLOCK_SIZE 4096

int encrypt(FILE *i, FILE *o, char *pk_fn)
{
    int ret = 0;
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char tmp_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char tmp_sk[crypto_box_SECRETKEYBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char c[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char n[crypto_box_NONCEBYTES];

    /* read the public key file */
    if ((ret = read_key_file(pk, sizeof(pk), pk_fn)) == 0) {
        /* write the signature */
        tmp_pk[0] = 'n';
        tmp_pk[1] = 'a';
        tmp_pk[2] = 0x00;
        tmp_pk[3] = 0x01;
        fwrite(tmp_pk, 4, 1, o);

        /* create a disposable set of keys:
           the public one shall be inside the encrypted stream
           aside with the encrypted symmetric key */
        crypto_box_keypair(tmp_pk, tmp_sk);

        /* create a random nonce */
        randombytes_buf(n, sizeof(n));

        /* create a random key */
        crypto_secretstream_xchacha20poly1305_keygen(key);

        /* now encrypt the symmetric key using the pk and the disposable sk */
        if (crypto_box_easy(c, key, sizeof(key), n, pk, tmp_sk) == 0) {
            unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
            crypto_secretstream_xchacha20poly1305_state st;
            unsigned char bi[BLOCK_SIZE];
            unsigned char bo[BLOCK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
            int eof;
            unsigned long long l;

            /* write the disposable pk */
            fwrite(tmp_pk, sizeof(tmp_pk), 1, o);

            /* write the nonce */
            fwrite(n, sizeof(n), 1, o);

            /* write the encrypted symmetric key */
            fwrite(c, sizeof(c), 1, o);

            /* encrypt stream */
            crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
            fwrite(header, sizeof(header), 1, o);

            do {
                l = fread(bi, 1, sizeof(bi), i);
                eof = feof(i);

                crypto_secretstream_xchacha20poly1305_push(&st, bo, &l, bi, l, NULL,
                    0, eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0);

                fwrite(bo, 1, (size_t) l, o);
            } while (!eof);
        }
        else {
            ret = 4;
            fprintf(stderr, "ERROR: (%d) crypto_box_easy()\n", ret);
        }
    }

    return ret;
}


int decrypt(FILE *i, FILE *o, char *sk_fn)
{
    int ret = 0;
    unsigned char sk[crypto_box_PUBLICKEYBYTES];
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char c[crypto_box_MACBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char n[crypto_box_NONCEBYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char bi[BLOCK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char bo[BLOCK_SIZE];
    int eof;
    unsigned long long l;
    unsigned char tag;

    /* read the secret key */
    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) != 0)
        goto end;

    /* read 4 bytes */
    if (fread(pk, 4, 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) unexpected EOF reading signature\n", ret);
        goto end;
    }

    /* does it have a signature? */
    if (pk[0] == 'n' && pk[1] == 'a' && pk[2] == 0x00) {
        if (pk[3] == 0x01) {
            /* it does; read a full key */
            if (fread(pk, sizeof(pk), 1, i) != 1) {
                ret = 2;
                fprintf(stderr, "ERROR: (%d) unexpected EOF reading pk\n", ret);
                goto end;
            }
        }
        else {
            ret = 2;
            fprintf(stderr, "ERROR: (%d) signature for another format (%02x)\n", ret, pk[3]);
            goto end;
        }
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) bad signature\n", ret);
        goto end;
    }

    /* read the nonce + encrypted symmetric key */
    if (fread(n, sizeof(n), 1, i) == 1 && fread(c, sizeof(c), 1, i) == 1) {

        /* decrypt the symmetric key */
        if (!crypto_box_open_easy(key, c, sizeof(c), n, pk, sk)) {
            /* decrypt stream */

            /* read header */
            fread(header, sizeof(header), 1, i);

            /* init decryption */
            if (!crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key)) {
                do {
                    l = fread(bi, 1, sizeof(bi), i);
                    eof = feof(i);

                    if (crypto_secretstream_xchacha20poly1305_pull(&st, bo, &l, &tag,
                                                   bi, l, NULL, 0)) {
                        ret = 4;
                        fprintf(stderr, "ERROR: (%d) corrupted chunk\n", ret);
                        break;
                    }

                    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
                        ret = 2;
                        fprintf(stderr, "ERROR: (%d) premature end\n", ret);
                        break;
                    }

                    if (fwrite(bo, 1, (size_t) l, o) != l) {
                        ret = 3;
                        fprintf(stderr, "ERROR: (%d) write error\n", ret);
                        break;
                    }

                } while (!eof);
            }
            else {
                ret = 2;
                fprintf(stderr, "ERROR: (%d) incomplete header\n", ret);
            }
        }
        else {
            ret = 4;
            fprintf(stderr, "ERROR: (%d) crypto_box_open_easy()\n", ret);
        }
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) unexpected EOF reading header\n", ret);
    }

end:
    return ret;
}


char *usage_str="\
ttcdt <dev@triptico.com>\n\
This software is released into the public domain.\n\
\n\
Usage:\n\
\n\
  ttcdt-sodium -G -p pubkey -s seckey     Generate key pairs\n\
  ttcdt-sodium -R -p pubkey -s seckey     Regenerate pubkey from seckey\n\
  ttcdt-sodium -E -p pubkey               Encrypt STDIN to STDOUT\n\
  ttcdt-sodium -D -s seckey               Decrypt STDIN to STDOUT\n\
\n\
Examples:\n\
 (on desktop)\n\
 $ ttcdt-sodium -G -p ~/.key.pub -s ~/.key.sec\n\
 $ scp ~/.key.pub server:~/.key.pub\n\
 (on server, secret key not needed there)\n\
 $ (cd / && sudo tar czvf - etc/) | ttcdt-sodium -E -p ~/.key.pub > encrypted\n\
 (back on desktop, to restore)\n\
 $ ttcdt-sodium -D -s ~/.key.sec < encrypted > decrypted.tar.gz\n\
\n\
Both pubkey and seckey are ASCII base64 files.";

int usage(void)
{
    fprintf(stderr,
        "ttcdt-sodium %s - Tool for asymmetric encryption of files using libsodium\n",
        VERSION);
    fprintf(stderr, "%s\n", usage_str);

    return 1;
}


int main(int argc, char *argv[])
{
    int ret;
    char *pk_fn = NULL;
    char *sk_fn = NULL;
    char *cmd = NULL;

    if (!sodium_init()) {
        int n;

        for (n = 1; n < argc; n++) {
            char *p = argv[n];

            if (strcmp(p, "-G") == 0 || strcmp(p, "-R") == 0 ||
                strcmp(p, "-E") == 0 || strcmp(p, "-D") == 0)
                cmd = p;
            else
            if (strcmp(p, "-p") == 0)
                pk_fn = argv[++n];
            else
            if (strcmp(p, "-s") == 0)
                sk_fn = argv[++n];
        }

        if (cmd == NULL)
            ret = usage();
        else
        if (strcmp(cmd, "-G") == 0 && pk_fn && sk_fn)
            ret = generate_keys(pk_fn, sk_fn);
        else
        if (strcmp(cmd, "-R") == 0 && pk_fn && sk_fn)
            ret = rebuild_public_key(pk_fn, sk_fn);
        else
        if (strcmp(cmd, "-E") == 0 && pk_fn)
            ret = encrypt(stdin, stdout, pk_fn);
        else
        if (strcmp(cmd, "-D") == 0 && sk_fn)
            ret = decrypt(stdin, stdout, sk_fn);
        else
            ret = usage();
    }
    else {
        ret = 4;
        fprintf(stderr, "ERROR: (%d) cannot initialize libsodium\n", ret);
    }

    return ret;
}
