package com.dawn.appkeystore;

import android.app.Application;

public class MyApp extends Application {
    private static MyApp application;

    @Override
    public void onCreate() {
        super.onCreate();
        application = this;
    }


    public static MyApp getApplication() {
        return application;
    }
}
