/*
 * Commons eID Project.
 * Copyright (C) 2009-2012 FedICT.
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

import com.trust1t.android.sdk.eid.core.files.SpecialStatus;

/**
 * Data convertor for eID special constants.
 * 
 * @author Frank Cornelis
 * @see com.trust1t.android.sdk.eid.core.files.SpecialStatus
 */
public class SpecialStatusConvertor implements DataConvertor<SpecialStatus> {

	
	public SpecialStatus convert(final byte[] value)
			throws DataConvertorException {
		final String strValue = new String(value);
		return SpecialStatus.toSpecialStatus(strValue);
	}
}
