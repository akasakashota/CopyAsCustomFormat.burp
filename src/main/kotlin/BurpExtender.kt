package burp

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseEvent
import java.awt.event.MouseListener
import java.io.PrintWriter
import java.lang.Exception
import java.lang.RuntimeException
import javax.swing.JMenuItem
import kotlin.collections.MutableList


class BurpExtender : IBurpExtender, IContextMenuFactory {
    private lateinit var cb: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private lateinit var stdout: PrintWriter
    private lateinit var stderr: PrintWriter

    companion object {
        const val EXTENSION_NAME = "Copy As Custom Format"
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        callbacks?.also {
            cb = it
            helpers = cb.helpers
            stdout = PrintWriter(cb.stdout, true)
            stderr = PrintWriter(cb.stderr, true)
        } ?: throw RuntimeException("Runtime Exception at Registration")

        cb.setExtensionName(EXTENSION_NAME)
        cb.registerContextMenuFactory(this)

        out("Loaded successfully")
    }

    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        invocation?.let {
            val httpRequestResponseArray = it.selectedMessages
            val formattedItems = httpRequestResponseArray.map { i -> Formatting(i) }
            val item = JMenuItem("Copy as Custom Format")
            item.addMouseListener(CopyListener(formattedItems))
            return mutableListOf(item)
        }

        return mutableListOf()
    }

    /**
     * Convert to following format:
     *   <HTTP Method>\t<URL>\t<HTTP Request Body>\t<HTTP Response Body>\n
     *   ...
     * Note: If the body contains line breaks, it won't work as intended in Google Sheets.
     */
    private fun convert(items: Array<IHttpRequestResponse>): String {
        val sb = StringBuilder()

        items.forEach { http ->
        }

        return sb.toString()
    }

    private inner class CopyListener(private val formattedItems: List<Formatting>) : MouseListener {
        override fun mouseReleased(e: MouseEvent?) {
            try {
                val clip: Clipboard = Toolkit.getDefaultToolkit()!!.systemClipboard
                val ss = StringSelection(formattedItems.joinToString("\n"))
                clip.setContents(ss, ss)
                out("Copied ${formattedItems.size} item(s).")
            } catch (e: Exception) { err(e) }
        }

        override fun mouseClicked(e: MouseEvent?) {}
        override fun mousePressed(e: MouseEvent?) {}
        override fun mouseEntered(e: MouseEvent?) {}
        override fun mouseExited(e: MouseEvent?) {}
    }

    private inner class Formatting(private val http: IHttpRequestResponse) {
        private var method: String = ""
        private var url: String = ""
        private var requestBody: String = ""
        private var responseBody: String = ""

        init {
            try {
                val req = helpers.analyzeRequest(http)
                val res = helpers.analyzeResponse(http.response)

                method = req.method
                url = req.url.toString()
                requestBody = http.request.decodeToString(req.bodyOffset)
                responseBody = http.response.decodeToString(res.bodyOffset)
            } catch (e: Exception) { err(e) }
        }

        private fun parseRequestBody() {

        }

        private fun parseResponseBody() {

        }

        override fun toString(): String {
            return arrayOf(method, url, requestBody, responseBody).joinToString("\t")
        }
    }

    private fun out(msg: String) {
        stdout.println("[$EXTENSION_NAME][Info]: $msg")
    }
    private fun err(e: Exception) {
        stderr.println("[$EXTENSION_NAME][Error]: ${e.message}")
        e.printStackTrace(stderr)
    }
}