/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider;


import org.cloudfoundry.identity.uaa.authentication.GenericPasswordPolicy;

public class PasswordPolicy extends GenericPasswordPolicy<PasswordPolicy> {

    public static final String PASSWORD_POLICY_FIELD = "passwordPolicy";

    private int expirePasswordInMonths;

    public PasswordPolicy() {
        super();
        this.expirePasswordInMonths = -1;
    }

    public PasswordPolicy(int minLength,
                          int maxLength,
                          int requireUpperCaseCharacter,
                          int requireLowerCaseCharacter,
                          int requireDigit,
                          int requireSpecialCharacter,
                          int expirePasswordInMonths) {
        super(minLength,
                maxLength,
                requireUpperCaseCharacter,
                requireLowerCaseCharacter,
                requireDigit,
                requireSpecialCharacter);
        this.expirePasswordInMonths = expirePasswordInMonths;
    }

    public int getExpirePasswordInMonths() {
        return expirePasswordInMonths;
    }

    public PasswordPolicy setExpirePasswordInMonths(int expirePasswordInMonths) {
        this.expirePasswordInMonths = expirePasswordInMonths;
        return this;
    }

    @Override
    public boolean allPresentAndPositive() {
        return super.allPresentAndPositive() && expirePasswordInMonths >= 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        PasswordPolicy that = (PasswordPolicy) o;

        return expirePasswordInMonths == that.expirePasswordInMonths;

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + expirePasswordInMonths;
        return result;
    }
}
