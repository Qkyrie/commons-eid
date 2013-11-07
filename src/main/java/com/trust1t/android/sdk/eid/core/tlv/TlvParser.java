/*
 * Commons eID Project.
 * Copyright (C) 2008-2012 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package com.trust1t.android.sdk.eid.core.tlv;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;


/**
 * Tag-Length-Value parser. The TLV-format is used in the eID card for encoding
 * of the identity and address files.
 *
 * @author Frank Cornelis
 *
 */
public class TlvParser {


    private TlvParser() {
        super();
    }

    /**
     * Parses the given file using the meta-data annotations within the tlvClass
     * parameter.
     *
     * @param <T>
     * @param file
     * @param tlvClass
     * @return
     */
    public static <T> T parse(final byte[] file, final Class<T> tlvClass) {
        T t;
        try {
            t = parseThrowing(file, tlvClass);
        } catch (final Exception ex) {
            throw new RuntimeException("error parsing file: "
                    + tlvClass.getName(), ex);
        }
        return t;
    }

    private static byte[] copy(final byte[] source, final int idx,
                               final int count) {
        final byte[] result = new byte[count];
        System.arraycopy(source, idx, result, 0, count);
        return result;
    }

    private static <T> T parseThrowing(final byte[] file,
                                       final Class<T> tlvClass) throws InstantiationException,
            IllegalAccessException, DataConvertorException,
            UnsupportedEncodingException {
        final Field[] fields = tlvClass.getDeclaredFields();
        final Map<Integer, Field> tlvFields = new HashMap<Integer, Field>();
        final T tlvObject = tlvClass.newInstance();
        for (Field field : fields) {
            final TlvField tlvFieldAnnotation = field
                    .getAnnotation(TlvField.class);
            if (null != tlvFieldAnnotation) {
                final int tagId = tlvFieldAnnotation.value();
                if (tlvFields.containsKey(new Integer(tagId))) {
                    throw new IllegalArgumentException("TLV field duplicate: "
                            + tagId);
                }
                tlvFields.put(new Integer(tagId), field);
            }
            final OriginalData originalDataAnnotation = field
                    .getAnnotation(OriginalData.class);
            if (null != originalDataAnnotation) {
                field.setAccessible(true);
                field.set(tlvObject, file);
            }
        }

        int idx = 0;
        while (idx < file.length - 1) {
            final byte tag = file[idx];
            idx++;
            byte lengthByte = file[idx];
            int length = lengthByte & 0x7f;
            while ((lengthByte & 0x80) == 0x80) {
                idx++;
                lengthByte = file[idx];
                length = (length << 7) + (lengthByte & 0x7f);
            }
            idx++;
            if (0 == tag) {
                idx += length;
                continue;
            }
            if (tlvFields.containsKey(new Integer(tag))) {
                final Field tlvField = tlvFields.get(new Integer(tag));
                final Class<?> tlvType = tlvField.getType();
                final ConvertData convertDataAnnotation = tlvField
                        .getAnnotation(ConvertData.class);
                final byte[] tlvValue = copy(file, idx, length);
                Object fieldValue;
                if (null != convertDataAnnotation) {
                    final Class<? extends DataConvertor<?>> dataConvertorClass = convertDataAnnotation
                            .value();
                    final DataConvertor<?> dataConvertor = dataConvertorClass
                            .newInstance();
                    fieldValue = dataConvertor.convert(tlvValue);
                } else if (String.class == tlvType) {
                    fieldValue = new String(tlvValue, "UTF-8");
                } else if (Boolean.TYPE == tlvType) {
                    fieldValue = true;
                } else if (tlvType.isArray()
                        && Byte.TYPE == tlvType.getComponentType()) {
                    fieldValue = tlvValue;
                } else {
                    throw new IllegalArgumentException(
                            "unsupported field type: " + tlvType.getName());
                }
                if (null != tlvField.get(tlvObject)
                        && false == tlvField.getType().isPrimitive()) {
                    throw new RuntimeException("field was already set: "
                            + tlvField.getName());
                }
                tlvField.setAccessible(true);
                tlvField.set(tlvObject, fieldValue);
            } else {
            }
            idx += length;
        }
        return tlvObject;
    }
}
