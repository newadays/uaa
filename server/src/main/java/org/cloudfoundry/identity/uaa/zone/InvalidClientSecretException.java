package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class InvalidClientSecretException extends UaaException{

    private final List<String> errorMessages;

    public InvalidClientSecretException(String message) {
        super(message, HttpStatus.BAD_REQUEST.value());
        errorMessages = Arrays.asList(message);
    }

    public InvalidClientSecretException(List<String> errorMessages) {
        super(StringUtils.collectionToDelimitedString(errorMessages, ","), HttpStatus.BAD_REQUEST.value());
        this.errorMessages = errorMessages;
    }

    public InvalidClientSecretException(String message, HttpStatus httpStatus) {
        super(message, httpStatus.value());
        errorMessages = Arrays.asList(message);
    }

    public List<String> getErrorMessages() {
        return errorMessages;
    }

    public String getMessagesAsOneString() {
        ArrayList<String> sortedMessages = new ArrayList<String>(errorMessages);
        Collections.sort(sortedMessages);
        return StringUtils.collectionToDelimitedString(sortedMessages, " ");
    }
}