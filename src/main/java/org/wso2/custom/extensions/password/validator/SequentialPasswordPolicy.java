package org.wso2.custom.extensions.password.validator;

import java.util.Map;

public class SequentialPasswordPolicy extends org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer {

    private static final int MAX_SEQUENTIAL_LIMIT = 3; // Allow up to 3 sequential characters
    private boolean SEQUENTIAL_CHECK_ENABLED = true;

    @Override
    public boolean enforce(Object... args) {

        if (args != null) {
            String password = args[0].toString();
            if (SEQUENTIAL_CHECK_ENABLED && hasSequentialCharacters(password)) {
                errorMessage = "Password contains too many sequential characters.";
                return false;
            }
        }
        return true;
    }

    @Override
    public void init(Map<String, String> properties) {

        if (properties != null && properties.size() > 0) {
            SEQUENTIAL_CHECK_ENABLED = Boolean.parseBoolean(properties.get("sequential.check.enabled"));
        }
    }

    private boolean hasSequentialCharacters(String password) {
        int sequentialCount = 1;
        for (int i = 1; i < password.length(); i++) {
            if (password.charAt(i) == password.charAt(i - 1) + 1) {
                sequentialCount++;
                if (sequentialCount > MAX_SEQUENTIAL_LIMIT) {
                    return true;
                }
            } else {
                sequentialCount = 1;
            }
        }
        return false;
    }

}
