package com.trust1t.android.sdk.eid.core.files;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * Created by KwintenP on 31/08/13.
 */
public class PinResult implements Parcelable{

    private boolean success;
    private int retriesLeft;
    private boolean blocked;

    public static final Creator<PinResult> CREATOR =
            new Creator<PinResult>(){

                
                public PinResult createFromParcel(Parcel source) {
                    return new PinResult(source);
                }

                
                public PinResult[] newArray(int size) {
                    return new PinResult[size];
                }
    };

    public PinResult(){

    }

  
    public int describeContents() {
        return 0;
    }

    public PinResult(Parcel source){
        readFromParcel(source);
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public int getRetriesLeft() {
        return retriesLeft;
    }

    public void setRetriesLeft(int retriesLeft) {
        this.retriesLeft = retriesLeft;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(((blocked) ? 1 : 0));
        dest.writeInt(retriesLeft);
        dest.writeInt((success)?1:0);
    }

    public void readFromParcel(Parcel source){
        setBlocked((source.readInt() == 1)?true:false);
        setRetriesLeft(source.readInt());
        setSuccess((source.readInt() == 1) ? true : false);
    }
}
