package burp

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseEvent
import java.awt.event.MouseListener
import java.io.PrintWriter
import java.lang.RuntimeException
import javax.swing.JMenuItem
import kotlin.collections.MutableList


class BurpExtender : IBurpExtender, IContextMenuFactory {
    private lateinit var cb: IBurpExtenderCallbacks
    private lateinit var helper: IExtensionHelpers
    private lateinit var stdout: PrintWriter
    private lateinit var stderr: PrintWriter

    companion object {
        const val EXTENSION_NAME = "Copy As Custom Format"
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        callbacks?.also {
            cb = it
            helper = cb.helpers
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
            val messages = convert(httpRequestResponseArray)
            out("Select ${httpRequestResponseArray.size} item${if (httpRequestResponseArray.size > 1) "s" else ""}")

            val item = JMenuItem("Copy as Custom Format")
            item.addMouseListener(CopyListener(messages))
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
            val req = helper.analyzeRequest(http)
            val res = helper.analyzeResponse(http.response)

            sb.append(
                arrayOf(
                    req.method,
                    req.url.toString(),
                    http.request.decodeToString(req.bodyOffset),
                    http.response.decodeToString(res.bodyOffset)
                ).joinToString("\t")
            )
            sb.append(System.lineSeparator())
        }

        return sb.toString()
    }

    private fun out(msg: String) {
        stdout.println("[$EXTENSION_NAME][Info]: $msg")
    }

    private fun err(msg: String) {
        stderr.println("[$EXTENSION_NAME][Error]: $msg")
    }
}

class CopyListener(private val str: String) : MouseListener {
    override fun mouseReleased(e: MouseEvent?) {
        val clip: Clipboard = Toolkit.getDefaultToolkit()!!.systemClipboard
        val ss = StringSelection(str)
        clip.setContents(ss, ss)
    }

    override fun mouseClicked(e: MouseEvent?) {}
    override fun mousePressed(e: MouseEvent?) {}
    override fun mouseEntered(e: MouseEvent?) {}
    override fun mouseExited(e: MouseEvent?) {}
}