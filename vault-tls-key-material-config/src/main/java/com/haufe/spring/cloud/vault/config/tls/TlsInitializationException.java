package com.haufe.spring.cloud.vault.config.tls;

/**
 * Exception that signals an error while setting up the TLS configuration.
 */
public class TlsInitializationException extends RuntimeException {

    /**
     * Constructs a new config server discovery exception with the specified detail message, but without any
     * cause.
     * <p>
     * This constructor treats {@link Throwable#addSuppressed(Throwable) suppression} as being enabled and
     * the stack trace as being {@link Throwable#setStackTrace(StackTraceElement[]) writable}.
     *
     * @param msg the detail message (which is saved for later retrieval
     *         by the {@link #getMessage()} method).
     */
    public TlsInitializationException(String msg) {
        this(msg, null);
    }

    /**
     * Constructs a new TLS initialization exception with the specified detail message and
     * cause.
     * <p>
     * This constructor treats {@link Throwable#addSuppressed(Throwable) suppression} as being enabled and
     * the stack trace as being {@link Throwable#setStackTrace(StackTraceElement[]) writable}.
     *
     * @param msg the detail message (which is saved for later retrieval
     *         by the {@link #getMessage()} method).
     * @param cause the cause (which is saved for later retrieval by the
     *         {@link #getCause()} method).  (A <tt>null</tt> value is
     *         permitted, and indicates that the cause is nonexistent or
     *         unknown.)
     */
    public TlsInitializationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
