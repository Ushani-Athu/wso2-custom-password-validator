package org.wso2.custom.extensions.password.validator;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.mgt.policy.PolicyRegistry;
import org.wso2.carbon.identity.mgt.policy.PolicyViolationException;
import org.wso2.carbon.identity.password.policy.constants.PasswordPolicyConstants;
import org.wso2.carbon.identity.password.policy.internal.IdentityPasswordPolicyServiceDataHolder;
import org.wso2.carbon.identity.password.policy.util.Utils;

import java.util.*;

public class CustomPasswordPolicyValidatorHandler extends AbstractEventHandler implements IdentityConnectorConfig {
    private static final Log log = LogFactory.getLog(CustomPasswordPolicyValidatorHandler.class);

    public CustomPasswordPolicyValidatorHandler() {
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        Map<String, Object> eventProperties = event.getEventProperties();

        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        Object credentials = eventProperties.get(IdentityEventConstants.EventProperty.CREDENTIAL);

        Property[] identityProperties;
        try {
            identityProperties = IdentityPasswordPolicyServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving password policy properties.", e);
        }

        boolean passwordPolicyValidation = false;
        String entropyCheckEnabled = "false";
        String passwordSequentialValidation = "false";
        String passwordTimeSensitiveValidation = "false";
        String timeSensitivePattern = ".*[A-Z].*[0-9].*[!@#$%^&*].*";

        for (Property identityProperty : identityProperties) {
            if (identityProperty == null) {
                continue;
            }
            String propertyName = identityProperty.getName();
            String propertyValue = identityProperty.getValue();

            if (CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE.equals(propertyName)) {
                passwordPolicyValidation = BooleanUtils.toBoolean(propertyValue);
                if (!passwordPolicyValidation) {
                    if (log.isDebugEnabled()) {
                        log.debug("Custom Password Policy validation is disabled");
                    }
                    return;
                }
                continue;
            } else if (CustomPasswordPolicyConstants.PASSWORD_SEQUENTIAL_POLICY_ENABLE.equals(propertyName)) {
                if (StringUtils.isNotBlank(propertyValue)) {
                    passwordSequentialValidation = propertyValue;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Sequential Password Policy validation not defined, hence not enabled");
                    }
                }
                continue;
            } else if (CustomPasswordPolicyConstants.PASSWORD_TIME_SENSITIVE_POLICY_ENABLE.equals(propertyName)) {
                if (StringUtils.isNotBlank(propertyValue)) {
                    passwordTimeSensitiveValidation = propertyValue;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Time Sensitive Password Policy validation not defined, hence not enabled");
                    }
                }
                continue;
            } else if (CustomPasswordPolicyConstants.ENTROPY_CHECK_ENABLED.equals(propertyName)) {
                entropyCheckEnabled = propertyValue;
        }

        }

        PolicyRegistry policyRegistry = new PolicyRegistry();
        String pwSequentialPolicyCls = configs.getModuleProperties().
                getProperty(CustomPasswordPolicyConstants.PASSWORD_SEQUENTIAL_POLICY_CLASS);
        String pwTimeSensitivePolicyCls = configs.getModuleProperties().
                getProperty(CustomPasswordPolicyConstants.PASSWORD_TIME_SENSITIVE_POLICY_CLASS);
        String pwEntropyPolicyCls = configs.getModuleProperties().
                getProperty(CustomPasswordPolicyConstants.ENTROPY_CHECK_CLASS);



        try {
            if (pwSequentialPolicyCls != null) { // **New block for Sequential Password Policy**
                SequentialPasswordPolicy sequentialPasswordPolicy = (SequentialPasswordPolicy) Class.
                        forName(pwSequentialPolicyCls).newInstance();
                HashMap<String, String> pwSequentialParams = new HashMap<>();
                pwSequentialParams.put("sequential.check.enabled", passwordSequentialValidation);
                sequentialPasswordPolicy.init(pwSequentialParams);
                policyRegistry.addPolicy(sequentialPasswordPolicy);
            }

            if (pwTimeSensitivePolicyCls != null) {
                TimeSensitivePasswordPolicy timeSensitivePasswordPolicy = (TimeSensitivePasswordPolicy) Class.
                        forName(pwTimeSensitivePolicyCls).newInstance();
                HashMap<String, String> pwTimeSensitiveParams = new HashMap<>();
                pwTimeSensitiveParams.put("time.sensitive.check.enabled", passwordTimeSensitiveValidation);
                pwTimeSensitiveParams.put("time.sensitive.pattern", timeSensitivePattern);
                timeSensitivePasswordPolicy.init(pwTimeSensitiveParams);
                policyRegistry.addPolicy(timeSensitivePasswordPolicy);
            }

            if (pwEntropyPolicyCls != null) {
            EntropyValidator entropyValidator = new EntropyValidator();
            HashMap<String, String> entropyParams = new HashMap<>();
            entropyParams.put("entropy.check.enabled", entropyCheckEnabled);
            entropyValidator.init(entropyParams);
            policyRegistry.addPolicy(entropyValidator);
            }

        } catch (Exception e) {
            throw Utils.handleEventException(
                    PasswordPolicyConstants.ErrorMessages.ERROR_CODE_LOADING_PASSWORD_POLICY_CLASSES, null, e);
        }

        try {
            policyRegistry.enforcePasswordPolicies(credentials.toString(), userName);
        } catch (PolicyViolationException e) {
            throw Utils.handleEventException(
                    PasswordPolicyConstants.ErrorMessages.ERROR_CODE_VALIDATING_PASSWORD_POLICY, e.getMessage(), e);
        }
    }


    @Override
    public String getName() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getFriendlyName() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getCategory() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap();
        nameMapping.put(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE, "Enable Custom Password Policy Feature");
        nameMapping.put(CustomPasswordPolicyConstants.ENTROPY_CHECK_ENABLED, "Enable Password Entropy Check"); // **New addition**
        nameMapping.put(CustomPasswordPolicyConstants.PASSWORD_SEQUENTIAL_POLICY_ENABLE, "Enable Password Sequential Policy");
        nameMapping.put(CustomPasswordPolicyConstants.PASSWORD_TIME_SENSITIVE_POLICY_ENABLE, "Enable Time Sensitive Policy");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap();
        descriptionMapping.put(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE, "Enable Custom Password Policy Feature");
        descriptionMapping.put(CustomPasswordPolicyConstants.ENTROPY_CHECK_ENABLED, "Enable or disable password entropy check");  // **New addition**
        descriptionMapping.put(CustomPasswordPolicyConstants.PASSWORD_SEQUENTIAL_POLICY_ENABLE, "Enable Password Sequential Policy");
        descriptionMapping.put(CustomPasswordPolicyConstants.PASSWORD_TIME_SENSITIVE_POLICY_ENABLE, "Enable Time Sensitive Policy");
        return descriptionMapping;
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {
        super.init(configuration);
        IdentityPasswordPolicyServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityConnectorConfig.class.getName(), this, null);
    }

    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE);
        properties.add(CustomPasswordPolicyConstants.ENTROPY_CHECK_ENABLED);
        properties.add(CustomPasswordPolicyConstants.PASSWORD_SEQUENTIAL_POLICY_ENABLE);
        properties.add(CustomPasswordPolicyConstants.PASSWORD_TIME_SENSITIVE_POLICY_ENABLE);
        return properties.toArray(new String[properties.size()]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {
        Map<String, String> defaultProperties = new HashMap();
        defaultProperties.put(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE));
        defaultProperties.put(CustomPasswordPolicyConstants.ENTROPY_CHECK_ENABLED,
                this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.ENTROPY_CHECK_ENABLED)); // New addition
        defaultProperties.put(CustomPasswordPolicyConstants.PASSWORD_TIME_SENSITIVE_POLICY_ENABLE,
                this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.PASSWORD_TIME_SENSITIVE_POLICY_ENABLE)); // New addition
        defaultProperties.put(CustomPasswordPolicyConstants.PASSWORD_SEQUENTIAL_POLICY_ENABLE,
                this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.PASSWORD_SEQUENTIAL_POLICY_ENABLE)); // New addition

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {
        return null;
    }
}