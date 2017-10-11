package com.github.bric3.blog.httpsventures.tools;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

public class MultiException<E extends Exception> {
    private final E parent;
    private boolean successMarker = false;

    public MultiException(E parent, Exception... exceptions) {
        this.parent = parent;
        Arrays.stream(exceptions).forEach(parent::addSuppressed);
    }

    public <T> MultiException<E> collectFrom(Stream<T> stream, ThrowingConsumer<T> invocation) {
        stream.forEach(t -> collect(t, invocation).ifPresent(parent::addSuppressed));
        return this;
    }

    private <T> Optional<Exception> collect(T type, ThrowingConsumer<T> throwing) {
        try {
            throwing.accept(type);

            successMarker = true;
            return Optional.empty();
        } catch (Exception e) {
            return Optional.of(e);
        }
    }

    public void scream(Mode mode) throws E {
        if (Mode.UNLESS_ANY_SUCCESS == mode && successMarker) {
            return;
        }
        if (parent.getSuppressed().length > 0) {
            throw parent;
        }
    }

    @FunctionalInterface
    public interface ThrowingConsumer<T> {
        void accept(T type) throws Exception;
    }

    public enum Mode {
        UNLESS_ANY_SUCCESS,
        ANY_FAILURE
    }
}
