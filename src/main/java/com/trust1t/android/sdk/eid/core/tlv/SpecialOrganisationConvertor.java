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

import com.trust1t.android.sdk.eid.core.files.SpecialOrganisation;

import java.io.UnsupportedEncodingException;

/**
 * Data convertor for special organisation eID identity field.
 * 
 * @author Frank Cornelis
 * 
 */
public class SpecialOrganisationConvertor
		implements
			DataConvertor<SpecialOrganisation> {

	
	public SpecialOrganisation convert(final byte[] value)
			throws DataConvertorException {
		if (null == value) {
			return SpecialOrganisation.UNSPECIFIED;
		}
		String key;
		try {
			key = new String(value, "UTF-8");
		} catch (final UnsupportedEncodingException uex) {
			throw new DataConvertorException("string error: "
					+ uex.getMessage());
		}
		final SpecialOrganisation specialOrganisation = SpecialOrganisation
				.toSpecialOrganisation(key);
		return specialOrganisation;
	}
}
