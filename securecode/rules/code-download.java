import java.net.URL;
import java.net.URLClassLoader;

class CodeDownloadTest {

    Object plugin(String jarUrl) throws Exception {
        // ruleid: kisa-code-download-classloader
        URLClassLoader loader = new URLClassLoader(new URL[]{new URL(jarUrl)});
        return loader.loadClass("Plugin").getDeclaredConstructor().newInstance();
    }

    ClassLoader other(URL[] urls) {
        // ruleid: kisa-code-download-classloader
        return URLClassLoader.newInstance(urls);
    }

    ClassLoader current() {
        // ok: kisa-code-download-classloader
        return Thread.currentThread().getContextClassLoader();
    }
}
