# zkSNARKS as a means to preserve the Privacy of personal financial data


## 1. Introduction

### 1.1 Taking a loan from a financial institution

One of the most common operations in financial institutions is taking a loan. However, there is always a risk for the lender that the debtor won't be able to repay his loan in time what will entail additional costs for the lender. When such a situation occurs, in a normal situation the amount of payment with interest will be debited from a debtor bank account or by selling debtor collateral. In the worst-case scenario, some of the client's property might be arrested due to judicial procedure and sold in favor of the bank. However, such a procedure is very complicated and there is always a risk that the value of the debtor property won't cover the amount of the debt left and the lender will incur a loss.

### 1.2 Credit reporting agencies as a buffer between lender and debtor

Therefore, when an individual applies for a loan, the financial institution must determine if a borrower is credit-worthy and will be able to pay off the loan. Because most credit organizations compete with each other, they are usually not willing to share information with each other whether an individual missed a payment or not. As a solution to that problem, all relevant information about past lenders, income, current loan status are collected and stored by the credit reporting agencies (e.g Equifax, Experian, Illion). Based on that information, an individual personal rating is calculated and presented as a **credit score**. Financial institutions then can pay agencies to access the data about any person, whether they want to extend their loan or even advertise their services.


### 1.3 Risks of storing your data in reporting agencies

However, as a consequence, all personal credit information is concentrated and stored in a reporting agency, which is mostly concerned about their clients - financial institutions, and doesn't have a strong incentive to protect consumer's personal information. And if any of such agencies is successfully attacked, this might lead to a huge loss of private credit information of millions of people. As an example, one of the biggest agencies in the USA, Equifax, [was breached in 2017](https://krebsonsecurity.com/2017/09/breach-at-equifax-may-impact-143m-americans/) and data of more than 147 million Americans might have been compromised.

## 2. Our solution to the problem

### 2.1 Using zkSNARK to generate a secure proof of credit score

In this document, we propose a privacy-guaranteed credit score evaluation method using the zero-knowledge proof. Currently, individuals applying for a loan have no means to know how the data provided by the reporting agency is used and stored in the financial institutions which issue a loan. So there is always a  risk, that such sensitive data will be compromised or used for advertising without an individual's knowledge.


Using the proposed method, an individual will be guaranteed that his private financial information is safe, secure, and not shared with any institution directly. 


![](https://i.imgur.com/sjTqAYS.png)


### 2.2 Implementation

As a toy example, let us imagine a person names Jane who wants to apply for a loan in a bank, to do so she has to provide information about her ability to pay off that loan.

1. Firstly, Jane acquire information about her **income** from a Public Agency (e.g government)
2. Then she collects her **account age** from financial institutions in which she has or had account and information about **previous overdue loans**.
3. Then using this information, Jane will request a trusted authority (e.g government) to generate proving and verification keys for her and then deploy a contact.

4. zkSNARK then will be able to generate proof that her credit score is high enough to apply for a loan in a certain bank. For the zkSNARK will use keys and the data provided by Jane.

**To illustrate our example, we will use a toy formula to calculate a credit score**

The private inputs are:
```
- income = 5000
- account_age = 10
- overdue_loans = 2
```

To determine the credit score, in our example formula we will use dummy weight as multipliers:

```
- base = 100000
- income_weight = 1
- overdue_weight = 10000
- account_age_weight = 5000
```

So the final formula will look like:

`score = base + (income * income_weight) + (account_age * account_age_weight) - (overdue_loans * overdue_loans * overdue_loans_weight)`

In Jane's case, her credit score will be '115000'.

5. After that, if Jane will apply for a loan, a financial institution will provide a minimum credit score requirement to get such a loan as public input. 

6. Then Jane will be able to generate a proof using zkSNARK and either valid or invalid proof will be generated depending on whether Jane's credit score is higher/equal to the requirement or not.
Another important note, if Jane will provide any incorrect data in her private input, the generated proof will be invalid. Thus preventing the user from manipulating the data in order to get a better score.

6. A financial institution then will be able to verify the proof using the verification key and data from the public inputs to make sure that the user provided correct information. 


7. Depending on the proof, a lender might decide whether he will accept or decline Jane's appliance.
A great benefit from using zkSNARK is that a financial institution won't get any of Jane's personal data, but only the proof and public inputs. With zero-knowledge proof, Jane can be sure, that her financial information is safe and only available to her.



## Usage

#### 1. Build the cli

```bash
git clone --recursive https://github.com/Iysbaera/ton-proof-verification-contest
cd ton-proof-verification-contest
mkdir build && cd build
cmake ..
make cli
```

#### 2. Generate keys

`./bin/cli/cli --setup`


#### 3. Generate proof using the private user data as well as public hashes as a parameters

```bash
./bin/cli/cli --proof \
              --id 123 \
              --income 20000 \
              --overdue-loans 2 \
              --account-age 3 \
              --pa-data-hash 600684A1506162C12B207FE25EBFE7A2EEB036ABD1876B650AE448090639F014 \
              --fi-data-hash EE692E243CCE7D445512AADBFF5302BB2B47E9CC6DBB4C3141D1F9636B21E806
```

Proof file will be saved to file "proof" and serialized primary input to the "pi" file. Now, we can verify proof on the blockchain

#### 4. Verification
Assuming we have `tondev` and nil's solidity compiler installed, we will convert `verification key`, `proof` and `primary input` to hex and verify using deployed smart contract
```bash
cd ../contract
tondev sol compile verification
tondev contract deploy verification
cat ../build/v_key | xxd -p -c 10000 > key.hex
cat ../build/proof | xxd -p -c 10000 > proof.hex
cat ../build/pi | xxd -p -c 10000 > pi.hex
tondev contract run verification setVerificationKey -p -i vkey:$(cat key.hex)
tondev contract run verification verify -p -i proof:$(cat proof.hex),pi:$(cat pi.hex)
```

## Conclusion

I see the great prospects in using zkSNARKs in the financial sector as a means to conduct fully privacy-secure transactions between individuals and institutions. Although my idea is still a proof of concept, I believe that in the near future such blockchain solutions will achieve mass adoption in the financial sector.
