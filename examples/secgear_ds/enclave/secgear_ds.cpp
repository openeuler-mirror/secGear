/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include <cstdarg>
#include <string>
#include <vector>
#include "secgear_ds_t.h"
#include "status.h"

const int BUF_LEN = 32;
const int MAX_ITEM_NUM = 32768;
const int MAX_BUF_SIZE = 256;

const int NAME_SIZE = 32;
const int DESP_SIZE = 64;

using namespace std;

// 键值对拆分
typedef struct Value {
    string name;
    string address;
    string gender;
    string description;
} Value, *ValuePtr;

typedef struct Key {
    // key information
    int32_t key_info;
    // pointer to value
    Value *ptr;
} Key, *KeyPtr;

// 键值对统一存放
typedef struct KV {
    int32_t key_info;
    char name[NAME_SIZE + 1];
    char address[NAME_SIZE + 1];
    char gender[NAME_SIZE + 1];
    char description[DESP_SIZE + 1];
}KV, *KVPtr;

// 节点结构体
typedef struct BSTNode{
	int key;
	int height;
	int data;
	BSTNode *left,*right;
	BSTNode()=default;
	BSTNode(int k):key(k),height(1),data(0),left(NULL),right(NULL){}
}BSTree;
// 顺序表
typedef struct OrderList {
    int* key_list;
    uint32_t len;
}OrderList;
// 链表节点
typedef struct Node {
    int32_t key;
    struct Node *next;
}Node, *pNode;
// 链表
typedef struct LinkList {
    pNode head;
    uint32_t len;
}LinkList;

static BSTree* rt;         // 树根
static OrderList *ol;      // 顺序表
static LinkList L;         // 链表
static Key *key_ptr;   // 键值对全局指针
static vector<Key> key_list;   // 键值对列表
static int32_t ITEM_NUM = 0;   // 数据数量
static uint64_t ptr_addr[BUF_LEN];
static KV *kv_list;
static uint32_t len_kv = 0;

// 初始化
int init_key(uint64_t* key_base_addr, uint32_t buf_len) 
{
    if (buf_len < 1) return -1;
    ITEM_NUM = buf_len;
    key_ptr = new Key[buf_len];     // 分配空间
    KeyPtr temp_ptr = (KeyPtr)key_base_addr[0];
    memcpy(key_ptr, (KeyPtr)key_base_addr[0], buf_len*sizeof(Key));    // 内存拷贝
    for (int i = 0; i < ITEM_NUM; i++) {
        key_list.push_back(key_ptr[i]);
    }
    return 0;
}
// 查找函数
int Search(int32_t k) 
{
    int i = 0;
    for (i = 0; i < key_list.size(); i++) {
        if (key_list[i].key_info == k) {
            return i;
        }
    }
    return -1;
}
// 查找接口
int search_kv(int32_t* search_list, uint64_t* ret_addr, uint32_t buf_len)
{
    int32_t k = search_list[0]; // 查询键值对
    int i = Search(k);          // 键值对是否存在
   
    if (i > -1) {
        Value *value = key_list[i].ptr;
        ret_addr[0] = (uint64_t)value;
        return 0;
    }
    return -1;
}
// 插入函数
void Insert(Key key)
{
    key_list.push_back(key);
}
// 插入接口
int insert_kv(uint64_t* insert_list, uint32_t buf_len)
{
    Key key;
    
    KeyPtr ptr = (KeyPtr)insert_list[0];
    key.key_info = ptr->key_info;
    key.ptr = ptr->ptr;
    Insert(key);
    
    if (Search(key.key_info)> -1) {
        return 0;
    }
    return -1;
}
// 更新函数
int Update(int32_t k, Value* new_value)
{
    int index = Search(k);
    if (index < 0) {
        return -1;
    }
    // 这种方式是否会造成内存泄漏
    key_list[index].ptr = new_value;
    return 0;
}
// 更新接口
int update_kv(uint64_t* update_list, int32_t kk, uint32_t buf_len) 
{
    ValuePtr new_value = (ValuePtr)update_list[0];  // 值指针
    int res = Update(kk, new_value);
    if (res < 0) {
        return -1;
    }
    return 0;
}

// 删除函数
int Delete_(int32_t k)
{
    int index = Search(k);
    int len = key_list.size();
    key_list[index] = key_list[len-1];  // 将最后一个元素移动到当前位置
    key_list.pop_back();                // 删除最后一个元素，但保持容量不变
    index = Search(k);
    if (index < 0) {
        return 0;
    }
    return -1;
}
int Delete(int32_t k) 
{
    int index = Search(k);
    int len = key_list.size();
    return 0;
}
// 删除接口
int delete_kv(int32_t* delete_list, uint32_t buf_len)
{
    int32_t k = delete_list[0];
    if (Delete_(k) < 0) {
        return -1;
    }
    return 0;
}
///////////////////////////////////////////////
// 统一存放
int init_keyvalue(uint64_t init_keyvalue, uint32_t buf_len)
{
    if (buf_len < 1) return -1;
    kv_list = new KV[MAX_ITEM_NUM];
    KVPtr temp = (KVPtr)init_keyvalue;
    memcpy(kv_list, temp, buf_len*sizeof(KV));
    len_kv = buf_len;
    return 0;
}

uint32_t concat_char(char *&value, char *temp, uint32_t shift, uint32_t len)
{
    int i;
    temp[len - 1] = ' ';
    for (i = 0;i < len;i++) {
        value[shift + i] = temp[i];
        // ocall_print(temp[i]);
    }
    return i;

}
int search_keyvalue(uint64_t ret_addr, int32_t key)
{
    char *value = (char*)ret_addr;
    for (int i = 0;i < len_kv;i++) {
        if (kv_list[i].key_info == key) {
            int shift = concat_char(value, kv_list[i].name, shift, sizeof(kv_list[i].name));
            shift = concat_char(value, kv_list[i].address, shift, sizeof(kv_list[i].address));
            shift = concat_char(value, kv_list[i].gender, shift, sizeof(kv_list[i].name));
            concat_char(value, kv_list[i].description, shift, sizeof(kv_list[i].name));
            return i;
        }
    }
    return -1;
}

int insert_keyvalue(uint64_t kv_addr, int32_t key)
{
    KV kv;
    char *temp = new char[sizeof(KV)];
    KV * kv_temp = (KV*)kv_addr;
    int index = search_keyvalue((uint64_t)temp, key);
    if (index > -1) {
        return -1;
    }
    kv.key_info = key;
    memcpy(kv.name, kv_temp->name, sizeof(kv_temp->name));
    memcpy(kv.address, kv_temp->address, sizeof(kv_temp->address));
    memcpy(kv.gender, kv_temp->gender, sizeof(kv_temp->gender));
    memcpy(kv.description, kv_temp->description, sizeof(kv_temp->description));

    // kv.key_info = key;
    kv_list[len_kv++] = kv;
    return 0;
}

int delete_keyvalue(int32_t key)
{
    char *temp = new char[sizeof(KV)];
    int index = search_keyvalue((uint64_t)temp, key);
    if (index < 0) {
        return -1;
    }
    for (int i = index;i < len_kv - 1;i++) {
        kv_list[i] = kv_list[i+1];
    }
    len_kv--;
    return 0;
}

// 插入链表
int InsertLL(int32_t key)
{
	Node *temp = new Node();
	temp->key =key;
	temp->next = NULL;
	pNode pre = L.head;
	pNode cur = pre->next;
	while (cur&&key < cur->key) {
		pre = cur;
		cur = cur->next;
	}
	temp->next = pre->next;
	pre->next = temp;
	L.len++;
	return 0;
}

// 初始化链表
int InitLL(uint64_t key_list_addr, uint32_t buf_len)
{
	if (buf_len < 0) return -1;
	int32_t* elem_list = (int32_t*)key_list_addr;
	L.len = 0;
	L.head = new Node();
	L.head->next = NULL;
	pNode node;
	for (int i = 0;i < buf_len;i++) {
		InsertLL(elem_list[i]);
	}
    return 0;
}
// 查询链表
int SearchLL(int32_t key)
{
	if (L.head->next == NULL) return -1;
	pNode temp = L.head->next;
	while(temp) {
		if (temp->key == key) {
			return 0;
		}
		temp = temp->next;
	}
    return -1;
}

// 删除链表
int DeleteLL(int32_t key)
{
	if (SearchLL(key) < 0) return -1;
	pNode pre = L.head;
	pNode cur = pre->next;
	if (cur->key != key) {
		pre = cur;
		cur = cur->next;
	}
	pre->next = cur->next;
	free(cur);
    return 0;
}

int GetHeight(BSTree *rt){	//得到高度 
	if(rt == nullptr)	return 0;
	return rt->height;
}

void UpdateHeight(BSTree *rt){	//更新高度 
	if(rt == NULL)	return;
	rt->height = max(GetHeight(rt->left), GetHeight(rt->right)) + 1;
}

//左左调整(bf=2)，右旋，左子节点变成父节点，其多余的右子节点变成降级节点的左子节点 
void UpdateLL(BSTree *&rt){
	BSTree *pl=rt->left;
	rt->left=pl->right;
	pl->right=rt;
	rt=pl;
	UpdateHeight(rt->left);
	UpdateHeight(rt->right);
	UpdateHeight(rt);
}

//右右调整
void UpdateRR(BSTree *&rt){
	BSTree *pr=rt->right;
	rt->right=pr->left;
	pr->left=rt;
	rt=pr;
	UpdateHeight(rt->left);
	UpdateHeight(rt->right);
	UpdateHeight(rt);
}

//左右调整(bf=2),先对左子节点左旋调整为左左型，再进行左左调整 
void UpdateLR(BSTree *&rt){
    // cout << "ergfws " << rt->left->key <<  " vervg";
	UpdateRR(rt->left);
	UpdateHeight(rt->left->left);
	UpdateHeight(rt->left->right);
	UpdateHeight(rt->left);
	
	UpdateLL(rt);
	UpdateHeight(rt->left);
	UpdateHeight(rt->right);
	UpdateHeight(rt);
}

//右左调整(bf=-2),先对右子节点右旋调整为右右型，再进行右右调整 
void UpdateRL(BSTree *&rt){
	UpdateLL(rt->right);
	UpdateHeight(rt->right->left);
	UpdateHeight(rt->right->right);
	UpdateHeight(rt->right);
	
	UpdateRR(rt);
	UpdateHeight(rt->left);
	UpdateHeight(rt->right);
	UpdateHeight(rt);
}

BSTree* SearchBST(BSTree *rt, int k){		//查找
	if(rt==NULL||k==rt->key)	return rt;
	if(k<rt->key)	return SearchBST(rt->left,k);
	else	return SearchBST(rt->right,k);
}

/*
插入节点操作，先插入节点，再对其影响的祖先节点进行平衡调整，同时更新其节点高度。 
节点A的平衡调整可分为四种情况：
一、LL型：在A节点的左孩子的左子树上插入节点，导致A节点的平衡因子变为2。
可对其进行右旋，将A的左孩子代替A成为根节点，而原A的左孩子的右子树成为A的左子树。 
二、RR型：与LL型相反，是在A节点的右孩子的右子树上插入节点，导致A节点的平衡因子变为-2。
可对其进行左旋，将A的右孩子代替A成为根节点，而原A的右孩子的左子树成为A的右子树。
三、LR型：在A节点的左孩子的右子树上插入节点，导致A节点的平衡因子变为2。
可先对A的左孩子进行左旋操作（RR型），再对A节点进行右旋操作（LL型）。
四、RL型：在A节点的右孩子的左子树上插入节点，导致A节点的平衡因子变为-2。
可先对A的左孩子进行右旋操作（LL型），再对A节点进行左旋操作（RR型）。 
*/
bool InsertBST(BSTree *&rt, int k){		//插入 
	if(rt==NULL){
		rt=new BSTNode(k);
		return true;
	}
	if(k==rt->key)	return false;
	bool res=true;
	if(k<rt->key){
		res=InsertBST(rt->left,k);
		if(res&&GetHeight(rt->left)-GetHeight(rt->right)>1){
			if(k<rt->left->key)	UpdateLL(rt);	//左左
			else	UpdateLR(rt);				//左右 
		}
	}else{
		res=InsertBST(rt->right,k);
		if(res&&GetHeight(rt->left)-GetHeight(rt->right)<-1){
			if(k>rt->right->key)	UpdateRR(rt);	//右右 
			else	UpdateRL(rt);					//右左 
		}
	}
	if(res) UpdateHeight(rt);
	return res;
}

void DeleteBST_(BSTree *&rt, BSTree *pt){		//删除节点有左右子树时处理 
	if(rt->right==NULL){
		BSTree *p=rt;
		pt->key=rt->key;
		rt=rt->left;
		delete p;
	}else{
		DeleteBST_(rt->right,pt);
		if(GetHeight(rt->left)-GetHeight(rt->right)>1){
			UpdateLL(rt);					//左左 
		}
	}
	UpdateHeight(rt);
}

/*
删除节点操作。可先删除节点，再对其影响的祖先节点进行平衡调整，同时更新其节点的高度。 
同二叉排序树相同，删除节点分三种情况
一：被删除节点没有孩子节点，则直接删除即可
二：被删除节点只有一个孩子节点，则将其孩子节点代替删除节点的位置，随后删除节点即可
三：被删除节点有左右孩子，则可移花接木，即取左子树的最大值（也可取右子树的最小值）存放在被删除节点中，随后删除左子树的最大值的节点即可 
对于情况一，可同情况二处理
而对于平衡调整，需先更新其节点的高度，对于情况三处理时也需更新其节点高度，
再对其左右子树高度判断其为哪种平衡调整，调整时同时更新其节点高度 
*/
bool DeleteBST(BSTree *&rt, int k){		//删除
	if(rt==NULL)	return false;
	bool res = true;
	if(rt->key == k){
		if(rt->left == NULL){
			rt=rt->right; 
		} else if(rt->right==NULL){
			rt=rt->left;
		} else {
			DeleteBST_(rt->left,rt);
		}
	} else if (k < rt->key) {
		res = DeleteBST(rt->left,k);
		if(res && GetHeight(rt->left) - GetHeight(rt->right) > 1) {
			if(k<rt->left->key)	{
                UpdateLL(rt);	//左左
            } else {
                UpdateLR(rt);	//左右
            }
		} else if (res && GetHeight(rt->left) - GetHeight(rt->right) < -1) {
			if(k < rt->right->key) {
                UpdateRR(rt);	//右右 
            } else {
                UpdateRL(rt);					//右左
            } 
		}
	} else {
		res = DeleteBST(rt->right,k);
		if(res && GetHeight(rt->left) - GetHeight(rt->right) > 1) {
			if(k < rt->left->key)	{
                UpdateLL(rt);	//左左
            } else {
                if(rt->left->right) {
                    UpdateLR(rt);
                } else {
                    UpdateLL(rt);
                }
            }				//左右 
		} else if (res && GetHeight(rt->left) - GetHeight(rt->right) < -1){
			if(k > rt->right->key) {
                UpdateRR(rt);	//右右
            } else	{
                if (rt->right->left) {
                    UpdateRL(rt);					//右左 

                } else {
                    UpdateRR(rt);
                }
            }
		}
	}
	if(res)	{
        UpdateHeight(rt);
    }
    return res;
}

void InorderTraversal(BSTree *rt){	//中序遍历 
	if(rt==NULL)	return;
	InorderTraversal(rt->left);
    InorderTraversal(rt->right);
}

bool Judge(BSTree *rt){		//判断是否为AVL
	if(rt==NULL)	return true;
	if(Judge(rt->left)&&Judge(rt->right)&&abs(GetHeight(rt->left)-GetHeight(rt->right))<=1)	return true;
	return false;
}

// 初始化接口
int Initavl(uint64_t* insert_list, uint32_t buf_len)
{
    rt = new BSTree();
    int32_t *temp_list = (int32_t*)insert_list[0];
    for (int i = 0;i < buf_len; i++) {
        if (!InsertBST(rt, temp_list[i])) {
            return -1;
        }
    }
    return 0;
}

// 插入ecall接口（批量插入）
int Insertavl_(uint64_t *insert_list, uint32_t buf_len)
{   
    int32_t *temp_list = (int32_t*)insert_list[0];
    for (int i = 0;i < buf_len; i++) {
        if (!InsertBST(rt, temp_list[i])) {
            return -1;
        }
    }
    return 0;
}
// 插入ecall接口（单条数据插入）
int Insertavl(int32_t insert_element)
{
    if (!InsertBST(rt, insert_element)) {
        return -1;
    }
    return 0;
}

// 查询ecall接口
int Searchavl(int32_t search_key)
{
    BSTree *temp = SearchBST(rt, search_key);
    if (temp == NULL) {
        return -1;
    }
    return 0;
}

// 删除ecall接口
int Deleteavl(int32_t delete_key)
{
    if (!DeleteBST(rt, delete_key)) {
        return -1;
    }
    return 0;
}
int InitOL(uint64_t* insert_list, uint32_t buf_len) 
{
    ol = new OrderList();
    ol->key_list = new int[MAX_ITEM_NUM];        // 顺序表
    int32_t* temp_list = (int32_t*)insert_list[0];
    memcpy(ol->key_list, temp_list, buf_len*sizeof(int));
    ol->len = buf_len;                              // 记录个数
    sort(ol->key_list, ol->key_list+ol->len);       // 升序排列
    // ocall_print(ol->key_list[0]);
    return 0;
}
int InsertOL(int32_t key)
{
    if (ol->len >= MAX_ITEM_NUM) {
        return -1;
    }
    int index = SearchOL(key);
    ol->len += 1;
    for (int i = ol->len;i > index;i--) {
        ol->key_list[i] = ol->key_list[i-1];
    }
    ol->key_list[index] = key;
    return 0;
}

int SearchOL(int32_t key)
{
    for (int i = 0;i < ol->len;i++) {
        if (ol->key_list[i] == key) {
            return i;
        }
    }  
    return -1;
}
int DeleteOL(int32_t key)
{
    int index = SearchOL(key);
    if (ol->len <= 0 || index < 0) {     //表中无数据或不存在删除元素 
        return -1;
    }
    for (int i = index;i < ol->len - 1;i++) {
        ol->key_list[i] = ol->key_list[i+1];
    }
    ol->len -= 1;
    return 0;
}
/*
void LevelOrder(BSTree* root) {	//层序遍历 
    if(root==NULL)  return;
    queue<BSTree*> que;
    que.push(root);
    int n;
    BSTree *rt;
    cout << "层序遍历：当前节点 (高度) = 左节点 右节点"<<endl; 
    while(!que.empty()){
    	n=que.size();
    	while(n--){
    		rt=que.front();	que.pop();
        	cout<<rt->key<<" ("<<rt->height<<")\t=\t";
        	if(rt->left)	cout<<rt->left->key<<"\t";
        	else cout<<"#\t";
        	if(rt->right)	cout<<rt->right->key<<"\t";
        	else cout<<"#\t";
        	cout<<endl;
        	if(rt->left)	que.push(rt->left);
        	if(rt->right)	que.push(rt->right);
        }
	}
}
*/


