#include "storage_manager.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ITEMS 10000

static VaultItem* items[MAX_ITEMS];
static int item_count = 0;
static int next_item_id = 1;
static char items_db_file[] = "data/items.db";

/* 스토리지 관리자 초기화 */
int storage_manager_init(void) {
    FILE* fp = fopen(items_db_file, "rb");
    if (fp) {
        fread(&item_count, sizeof(int), 1, fp);
        fread(&next_item_id, sizeof(int), 1, fp);
        
        for (int i = 0; i < item_count; i++) {
            items[i] = malloc(sizeof(VaultItem));
            fread(items[i], sizeof(VaultItem), 1, fp);
            
            // blob은 별도로 읽기
            if (items[i]->blob_len > 0) {
                items[i]->blob = malloc(items[i]->blob_len);
                fread(items[i]->blob, 1, items[i]->blob_len, fp);
            } else {
                items[i]->blob = NULL;
            }
        }
        fclose(fp);
    }
    return 0;
}

/* 스토리지 관리자 정리 */
void storage_manager_cleanup(void) {
    FILE* fp = fopen(items_db_file, "wb");
    if (fp) {
        fwrite(&item_count, sizeof(int), 1, fp);
        fwrite(&next_item_id, sizeof(int), 1, fp);
        
        for (int i = 0; i < item_count; i++) {
            fwrite(items[i], sizeof(VaultItem), 1, fp);
            if (items[i]->blob_len > 0 && items[i]->blob) {
                fwrite(items[i]->blob, 1, items[i]->blob_len, fp);
            }
        }
        fclose(fp);
    }
    
    // 메모리 해제
    for (int i = 0; i < item_count; i++) {
        if (items[i]) {
            free(items[i]->blob);
            free(items[i]);
        }
    }
    
    // 상태 리셋 (init 실패 시 use-after-free 방지)
    item_count = 0;
    next_item_id = 1;
}

/* 아이템 저장 */
int storage_put_item(const char* owner_email, const unsigned char* iv,
                    const unsigned char* tag, const unsigned char* blob,
                    size_t blob_len, const char* meta) {
    if (item_count >= MAX_ITEMS) {
        return -1;
    }
    
    VaultItem* item = malloc(sizeof(VaultItem));
    if (item == NULL) {
        return -1;
    }
    item->id = next_item_id++;
    strncpy(item->owner_email, owner_email, sizeof(item->owner_email) - 1);
    memcpy(item->iv, iv, 12);
    memcpy(item->tag, tag, 16);
    
    item->blob = malloc(blob_len);
    if (item->blob == NULL) {
        free(item);
        return -1;
    }
    memcpy(item->blob, blob, blob_len);
    item->blob_len = blob_len;
    
    if (meta) {
        strncpy(item->meta, meta, sizeof(item->meta) - 1);
    } else {
        item->meta[0] = '\0';
    }
    
    item->created_at = time(NULL);
    
    items[item_count++] = item;
    
    // ID를 미리 저장 (cleanup에서 메모리 해제되기 전)
    int saved_id = item->id;
    
    // 즉시 저장
    storage_manager_cleanup();
    storage_manager_init();
    
    return saved_id;
}

/* 아이템 조회 */
VaultItem* storage_get_item(int item_id, const char* owner_email) {
    for (int i = 0; i < item_count; i++) {
        if (items[i]->id == item_id && 
            strcmp(items[i]->owner_email, owner_email) == 0) {
            return items[i];
        }
    }
    return NULL;
}

/* 아이템 수정 */
int storage_update_item(int item_id, const char* owner_email,
                        const unsigned char* iv, const unsigned char* tag,
                        const unsigned char* blob, size_t blob_len,
                        const char* meta) {
    for (int i = 0; i < item_count; i++) {
        if (items[i]->id == item_id &&
            strcmp(items[i]->owner_email, owner_email) == 0) {
            // 먼저 새 blob 준비 (실패 시 원본 데이터 보존)
            unsigned char* new_blob = malloc(blob_len);
            if (new_blob == NULL) {
                return -1;
            }
            memcpy(new_blob, blob, blob_len);
            
            // 모든 준비가 완료되면 한 번에 업데이트
            memcpy(items[i]->iv, iv, 12);
            memcpy(items[i]->tag, tag, 16);
            free(items[i]->blob);
            items[i]->blob = new_blob;
            items[i]->blob_len = blob_len;
            
            if (meta) {
                strncpy(items[i]->meta, meta, sizeof(items[i]->meta) - 1);
                items[i]->meta[sizeof(items[i]->meta) - 1] = '\0';
            } else {
                items[i]->meta[0] = '\0';
            }
            
            storage_manager_cleanup();
            storage_manager_init();
            
            return 0;
        }
    }
    return -1;
}

/* 아이템 목록 조회 */
VaultItem** storage_list_items(const char* owner_email, int* count) {
    VaultItem** result = malloc(sizeof(VaultItem*) * MAX_ITEMS);
    int result_count = 0;
    
    for (int i = 0; i < item_count; i++) {
        if (strcmp(items[i]->owner_email, owner_email) == 0) {
            result[result_count++] = items[i];
        }
    }
    
    *count = result_count;
    return result;
}

/* 아이템 삭제 */
int storage_delete_item(int item_id, const char* owner_email) {
    for (int i = 0; i < item_count; i++) {
        if (items[i]->id == item_id && 
            strcmp(items[i]->owner_email, owner_email) == 0) {
            free(items[i]->blob);
            free(items[i]);
            
            // 배열 재정렬
            for (int j = i; j < item_count - 1; j++) {
                items[j] = items[j + 1];
            }
            item_count--;
            
            storage_manager_cleanup();
            storage_manager_init();
            
            return 0;
        }
    }
    return -1;
}

/* 아이템 목록 메모리 해제 */
void storage_free_item_list(VaultItem** items_list, int count) {
    free(items_list);
}

