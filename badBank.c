#include <stdio.h>
#include <string.h>

struct BankAccount {
    char account_holder[32];  
    double balance;
    char transaction_memo[64]; 
};

void process_transaction(struct BankAccount *acct) {
    char memo[128]; 
    printf("Enter transaction memo: ");
    fgets(memo, sizeof (memo), stdin); 

    memo[strcspn(memo, "\n")] = '\0';
    
    strncpy(acct->transaction_memo, memo, sizeof(acct->transaction_memo) - 1);
    acct->transaction_memo[sizeof(acct->transaction_memo) - 1] = '\0';
}

void update_credentials(struct BankAccount *acct) {
    char new_name[200];
    printf("Enter new account name: ");
    fgets(new_name, sizeof(new_name), stdin);
    
    new_name[strcspn(new_name, "\n")] = '\0';

    if (strlen(new_name) >= sizeof(acct->account_holder)) {
        printf("Error: Name too long. Truncating to fit.\n");
    }
    
    strncpy(acct->account_holder, new_name, sizeof(acct->account_holder) - 1);
    acct->account_holder[sizeof(acct->account_holder) - 1] = '\0';
}

int main() {
    struct BankAccount acct = {"John Doe", 5000.0, "Initial deposit"};
    
    update_credentials(&acct);
    process_transaction(&acct);
    
    printf("\nAccount Summary:\nName: %s\nBalance: $%.2f\nLast Transaction: %s\n",
           acct.account_holder, acct.balance, acct.transaction_memo);
    return 0;
}
