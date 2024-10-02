# Custom Password Validators for WSO2 Identity Server
This repository contains custom password validators for WSO2 Identity Server (IS). These extensions enforce additional security policies during password creation or reset by checking password entropy, preventing sequential characters, and enforcing stricter rules during specific time periods.

## Validators

### 1. EntropyValidator
   Ensures that passwords have sufficient entropy (a measure of randomness) to resist brute-force attacks. Entropy is calculated based on the length of the password and the number of unique characters used.

### 2. SequentialPasswordPolicy
Prevents users from using passwords that contain too many sequential characters, such as abc, 123, or xyz. Sequential characters reduce password complexity and are easier to guess.
Default Maximum Sequential Limit: 3 (allows up to 3 sequential characters)

### 3. TimeSensitivePasswordPolicy
Enforces a stricter password policy during specific times of the day. Outside of these hours, a more relaxed policy may apply. This is useful for organizations that require stronger security during working hours.
Default Time Range: 9 AM to 6 PM
Default Pattern: Must contain at least one uppercase letter, one digit, and one special character.

## Build

Clone the repository and compile the Java classes using Maven. Package the classes into a .jar file.
```
mvn clean install
```

## Deploy

Copy the compiled .jar file to the WSO2 IS extensions directory: <IS_HOME>/repository/components/dropins/ directory.

##  Configure the Validator

Add the following configurations to the deployment.toml file in WSO2 IS to enable and configure the password validators.

```
[[event_handler]]
name= "CustomPasswordPolicyValidator"
subscriptions =["PRE_UPDATE_CREDENTIAL","PRE_UPDATE_CREDENTIAL_BY_ADMIN"]
[event_handler.properties]
enable = true
'class.EntropyValidator' = 'org.wso2.custom.extensions.password.validator.EntropyValidator'
'class.SequentialPasswordPolicy' = 'org.wso2.custom.extensions.password.validator.SequentialPasswordPolicy'
'class.TimeSensitivePasswordPolicy' = 'org.wso2.custom.extensions.password.validator.TimeSensitivePasswordPolicy'
'entropy.check.enable' = true  
'minEntropy' = 45.0  
'sequential.check.enable' = true  
'time.sensitive.check.enable' = true  

```
Start the server.
Navigate to the Management Console >> Identity Providers >> Resident, where you can view the custom password validator. From there, you can enable, disable, or configure the validator based on your specific requirements.

## Customization
You can modify the password policy logic to meet your custom requirements.




