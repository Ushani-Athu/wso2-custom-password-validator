package org.wso2.custom.extensions.password.validator;

public class CustomPasswordPolicyConstants {
    public static final String CUSTOM_PASSWORD_POLICY_ENABLE = "CustomPasswordPolicyValidator.enable";

    // Entropy Validator Constants
    public static final String ENTROPY_CHECK_ENABLED = "CustomPasswordPolicyValidator.entropy.check.enable";
    public static final String ENTROPY_CHECK_CLASS = "CustomPasswordPolicyValidator.class.EntropyValidator";

    // Time-Sensitive Validator Constants
    public static final String PASSWORD_TIME_SENSITIVE_POLICY_ENABLE = "CustomPasswordPolicyValidator.time.sensitive.check.enable";
    public static final String PASSWORD_TIME_SENSITIVE_POLICY_CLASS = "CustomPasswordPolicyValidator.class.TimeSensitivePasswordPolicy";

    // Sequential Password Validator Constants
    public static final String PASSWORD_SEQUENTIAL_POLICY_ENABLE = "CustomPasswordPolicyValidator.sequential.check.enable";
    public static final String PASSWORD_SEQUENTIAL_POLICY_CLASS = "CustomPasswordPolicyValidator.class.SequentialPasswordPolicy";

}
