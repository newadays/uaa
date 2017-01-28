package org.cloudfoundry.identity.uaa.zone;


import org.passay.*;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * <p>
 *      Requirements
 *      config.clientSecretPolicy.minLength    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.maxLength    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Maximum number of characters required for secret to be considered valid (defaults to 255).
 *      config.clientSecretPolicy.requireUpperCaseCharacter    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of uppercase characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.requireLowerCaseCharacter    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of lowercase characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.requireDigit    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of digits required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.requireSpecialCharacter    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Minimum number of special characters required for secret to be considered valid (defaults to 0).
 *      config.clientSecretPolicy.expiresecretInMonths    Number
 *              Required when clientSecretPolicy in the config is not null
 *                  Number of months after which current secret expires (defaults to 0).
 *
 */
public class ZoneClientSecretPolicyValidator implements ClientSecretValidator {


    private final ClientSecretPolicy globalDefaultClientSecretPolicy;

    public ZoneClientSecretPolicyValidator(ClientSecretPolicy globalDefaultClientSecretPolicy) {
        this.globalDefaultClientSecretPolicy = globalDefaultClientSecretPolicy;
    }

    @Override
    public void validate(String clientSecret) throws InvalidClientSecretException {
        if(clientSecret == null) {
            throw new InvalidClientSecretException("Client Secret cannot be null");
        }

        ClientSecretPolicy clientSecretPolicy = this.globalDefaultClientSecretPolicy;

        IdentityZone zone = IdentityZoneHolder.get();
        if(zone.getConfig().getClientSecretPolicy().getMinLength() != -1) {
            clientSecretPolicy = zone.getConfig().getClientSecretPolicy();
        }

        PasswordValidator clientSecretValidator = getClientSecretValidator(clientSecretPolicy);
        RuleResult result = clientSecretValidator.validate(new PasswordData(clientSecret));
        if (!result.isValid()) {
            List<String> errorMessages = new LinkedList<>();
            for (String s : clientSecretValidator.getMessages(result)) {
                errorMessages.add(s);
            }
            if (!errorMessages.isEmpty()) {
                throw new InvalidClientSecretException(errorMessages);
            }
        }

    }


    public PasswordValidator getClientSecretValidator(ClientSecretPolicy policy) {
        List<Rule> rules = new ArrayList<>();
        if (policy.getMinLength()>=0 && policy.getMaxLength()>0) {
            rules.add(new LengthRule(policy.getMinLength(), policy.getMaxLength()));
        }
        if (policy.getRequireUpperCaseCharacter()>0) {
            rules.add(new UppercaseCharacterRule(policy.getRequireUpperCaseCharacter()));
        }
        if (policy.getRequireLowerCaseCharacter()>0) {
            rules.add(new LowercaseCharacterRule(policy.getRequireLowerCaseCharacter()));
        }
        if (policy.getRequireDigit()>0) {
            rules.add(new DigitCharacterRule(policy.getRequireDigit()));
        }
        if (policy.getRequireSpecialCharacter() > 0) {
            rules.add(new SpecialCharacterRule(policy.getRequireSpecialCharacter()));
        }
        return new PasswordValidator(rules);
    }
}
