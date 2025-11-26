#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include <stddef.h>
#include <time.h>

/* Vault Item 구조체 */
typedef struct {
    int id;
    char owner_email[256];
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char* blob;
    size_t blob_len;
    char meta[256];
    time_t created_at;
} VaultItem;

/* 스토리지 관리자 초기화 */
int storage_manager_init(void);

/* 스토리지 관리자 정리 */
void storage_manager_cleanup(void);

/* 아이템 저장 */
int storage_put_item(const char* owner_email, const unsigned char* iv,
                    const unsigned char* tag, const unsigned char* blob,
                    size_t blob_len, const char* meta);

/* 아이템 조회 */
VaultItem* storage_get_item(int item_id, const char* owner_email);

/* 아이템 목록 조회 */
VaultItem** storage_list_items(const char* owner_email, int* count);

/* 아이템 삭제 */
int storage_delete_item(int item_id, const char* owner_email);

/* 아이템 메모리 해제 */
void storage_free_item(VaultItem* item);

/* 아이템 목록 메모리 해제 */
void storage_free_item_list(VaultItem** items, int count);

#endif /* STORAGE_MANAGER_H */

