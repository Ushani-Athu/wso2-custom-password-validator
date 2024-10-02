package org.wso2.custom.extensions.password.validator;

import java.util.Map;

public class EntropyValidator extends org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer {

    private static final double MIN_ENTROPY = 45.0;
    private boolean ENTROPY_CHECK_ENABLED = true;

    @Override
    public boolean enforce(Object... args) {

        if (args != null) {

            String password = args[0].toString();
            if (password.length() > 0 && ENTROPY_CHECK_ENABLED && !isValidEntropy(password)) {
                errorMessage = "Password entropy is too low.";
                return false;
            }
        }
        return true;
    }

    @Override
    public void init(Map<String, String> properties) {

        if (properties != null && properties.size() > 0) {
            ENTROPY_CHECK_ENABLED = Boolean.parseBoolean(properties.get("entropy.check.enabled"));
        }
    }

    private boolean isValidEntropy(String password) {
        int uniqueChars = (int) password.chars().distinct().count();
        double entropy = password.length() * Math.log(uniqueChars) / Math.log(2);
        return entropy >= MIN_ENTROPY;
    }

}
