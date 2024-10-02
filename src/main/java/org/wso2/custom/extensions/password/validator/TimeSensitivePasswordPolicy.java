package org.wso2.custom.extensions.password.validator;

import java.time.LocalTime;
import java.util.Map;

public class TimeSensitivePasswordPolicy extends org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer {

    private String SPECIAL_PATTERN = ".*[A-Z].*[0-9].*[!@#$%^&*].*"; // Example pattern
    private LocalTime startTime = LocalTime.of(9, 0);  // Start of stricter enforcement (09:00 AM)
    private LocalTime endTime = LocalTime.of(18, 0);   // End of stricter enforcement (06:00 PM)
    private boolean TIME_SENSITIVE_CHECK_ENABLED = true;

    @Override
    public boolean enforce(Object... args) {

        if (args != null) {
            String password = args[0].toString();
            LocalTime currentTime = LocalTime.now();

            // Check if current time falls within the time-sensitive window and apply stricter pattern
            if (TIME_SENSITIVE_CHECK_ENABLED && isWithinRestrictedTime(currentTime) && !password.matches(SPECIAL_PATTERN)) {
                errorMessage = "Password does not meet the required pattern for the current time.";
                return false;
            }
        }
        return true;
    }

    @Override
    public void init(Map<String, String> properties) {

        if (properties != null && properties.size() > 0) {
            TIME_SENSITIVE_CHECK_ENABLED = Boolean.parseBoolean(properties.get("time.sensitive.check.enabled"));
            String pattern = properties.get("time.sensitive.pattern");
            if (pattern != null) {
                SPECIAL_PATTERN = pattern;
            }
        }
    }

    private boolean isWithinRestrictedTime(LocalTime currentTime) {
        return (currentTime.isAfter(startTime) && currentTime.isBefore(endTime));
    }

}
