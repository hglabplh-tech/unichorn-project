package org.harry.security.util;

import iaik.pkcs.pkcs12.KeyBag;

import java.io.Serializable;

/**
 * Class representing a Tuple response
 * @param <F> the first object class
 * @param <S> the second object class
 */
public class Tuple<F,S> implements Serializable {

    public static final long serialVersionUID = 1378900L;
    /**
     * first element
     */
    private final F first;

    /**
     * second element
     */
    private final S second;

    /**
     * CTOr for creating a tuple
     * @param first first element
     * @param second second element
     */
    public Tuple(F first, S second) {
        this.first = first;
        this.second = second;
    }

    /**
     * get the first element
     * @return the object of type F
     */
    public F getFirst() {
        return first;
    }

    /**
     * get the second element
     * @return the object of type S
     */
    public S getSecond() {
        return second;
    }
}
