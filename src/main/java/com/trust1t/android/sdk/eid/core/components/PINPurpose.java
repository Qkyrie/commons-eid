/*
 * Commons eID Project.
 * Copyright (C) 2012-2013 FedICT.
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

package com.trust1t.android.sdk.eid.core.components;

import com.trust1t.android.sdk.eid.core.impl.FileType;

/**
 * a PINPurpose encapsulates the different reasons why the user's VERIFY_PIN code may be
 * requested: an authentication signature, a non-repudiation signature, or a user-requested 
 * test of their VERIFY_PIN code.
 * @author Frank Marien
 */
public enum PINPurpose {
	PINTest("test"), AuthenticationSignature("authentication"), NonRepudiationSignature(
			"nonrepudiation");

	private final String type;

	private PINPurpose(final String type) {
		this.type = type;
	}

	public String getType() {
		return this.type;
	}

	/**
	 * Determine the likely reason for a VERIFY_PIN request by checking the certificate chain
	 * involved.
	 * @param fileType the File on the BeID that is involved in the operation
	 * @return the VERIFY_PIN Purpose associated with this type of file
	 */
	public static PINPurpose fromFileType(final FileType fileType) {
		/**switch (fileType) {
			case AuthentificationCertificate :
				return AuthenticationSignature;
			case NonRepudiationCertificate :
				return NonRepudiationSignature;
			default :
				return PINTest;
		}*/
        return PINPurpose.PINTest;
	}
}
