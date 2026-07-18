// Astartis v2.1 — OS-Grade Dashboard JS
import "phoenix_html"
import {Socket} from "phoenix"
import {LiveSocket} from "phoenix_live_view"
import {hooks as colocatedHooks} from "phoenix-colocated/astartis_web"
import topbar from "../vendor/topbar"

const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")

let Hooks = {}

// Clock: update every second
Hooks.Clock = {
  mounted() { this.update(); this.timer = setInterval(() => this.update(), 1000) },
  destroyed() { clearInterval(this.timer) },
  update() {
    const now = new Date()
    const pad = n => String(n).padStart(2, '0')
    this.el.textContent =
      `${now.getUTCFullYear()}-${pad(now.getUTCMonth()+1)}-${pad(now.getUTCDate())} ` +
      `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())} UTC`
  }
}

// SystemTerminal: append events pushed from server, colour-code, filter
Hooks.SystemTerminal = {
  mounted() {
    this.filters = new Set(['TERM','PACKET','RULE','WORM','AGENT','AI','AUDIT','NAC','ZT','DECOY','SANDBOX','TICK'])
    this.autoScroll = true
    this.lineCount = 0
    this.MAX_LINES = 500

    // scroll lock detection
    this.el.addEventListener('scroll', () => {
      const el = this.el
      this.autoScroll = (el.scrollHeight - el.scrollTop - el.clientHeight) < 40
    })

    // server pushes terminal_line events
    this.handleEvent('terminal_line', ({tag, text, ts}) => {
      this.appendLine(tag, text, ts)
    })

    // filter toggle from buttons
    this.handleEvent('terminal_filter', ({tag, active}) => {
      if (active) this.filters.add(tag); else this.filters.delete(tag)
      this.applyFilters()
    })
  },

  appendLine(tag, text, ts) {
    if (this.lineCount >= this.MAX_LINES) {
      const first = this.el.querySelector('.tline')
      if (first) first.remove()
    }
    const colors = {
      TERM:'#0f62fe', PACKET:'#005d5d', RULE:'#8a6d00', WORM:'#da1e28', AGENT:'#0f62fe',
      AI:'#6929c4', AUDIT:'#198038', NAC:'#ba4e00', ZT:'#6929c4',
      DECOY:'#9f1853', SANDBOX:'#0072c3', TICK:'#6f6f6f'
    }
    const color = colors[tag] || '#525252'
    const div = document.createElement('div')
    div.className = `tline tline-${tag}`
    div.style.display = this.filters.has(tag) ? 'block' : 'none'
    div.innerHTML =
      `<span style="color:#6f6f6f;font-size:10px;margin-right:6px;">${ts}</span>` +
      `<span style="color:${color};font-weight:700;margin-right:6px;">[${tag}]</span>` +
      `<span style="color:#262626;">${escHtml(text)}</span>`
    // click to expand JSON
    div.title = text
    div.style.cursor = 'pointer'
    this.el.appendChild(div)
    this.lineCount++
    if (this.autoScroll) this.el.scrollTop = this.el.scrollHeight
  },

  applyFilters() {
    this.el.querySelectorAll('.tline').forEach(el => {
      const tag = el.className.replace('tline tline-', '')
      el.style.display = this.filters.has(tag) ? 'block' : 'none'
    })
  }
}

// PacketFlow: animate packet bar
Hooks.PacketFlow = {
  mounted() {
    this.frames = []
    this.animId = null
    this.handleEvent('packet_frame', ({entropy, anomalous}) => {
      this.frames.push({entropy, anomalous})
      if (this.frames.length > 80) this.frames.shift()
      this.draw()
    })
  },
  draw() {
    const el = this.el
    if (!el) return
    const chars = this.frames.map(f => {
      const e = f.entropy || 0
      const ch = e > 7.2 ? '█' : e > 5 ? '▓' : e > 3 ? '▒' : '░'
      const col = e > 7.2 ? '#da1e28' : e > 5 ? '#8a6d00' : '#198038'
      return `<span style="color:${col}">${ch}</span>`
    })
    el.innerHTML = chars.join('')
  }
}

// NACProgress: walking figure across 8 steps
Hooks.NACProgress = {
  mounted() {
    this.handleEvent('nac_step', ({step, total, pass}) => {
      const steps = this.el.querySelectorAll('.nac-step')
      steps.forEach((s, i) => {
        s.classList.remove('nac-active','nac-pass','nac-fail')
        if (i < step - 1) s.classList.add(pass ? 'nac-pass' : 'nac-fail')
        else if (i === step - 1) s.classList.add('nac-active')
      })
      const figure = this.el.querySelector('.nac-figure')
      if (figure) {
        const pct = ((step - 1) / (total - 1)) * 100
        figure.style.left = `${pct}%`
      }
    })
  }
}

// TrustGauge: fill SVG gauge arc
Hooks.TrustGauge = {
  mounted() {
    this.handleEvent('trust_score', ({score}) => {
      const arc = this.el.querySelector('.gauge-arc')
      if (!arc) return
      const pct = Math.min(100, Math.max(0, score)) / 100
      const r = 40, cx = 50, cy = 50
      const startAngle = -Math.PI * 0.75
      const endAngle = startAngle + Math.PI * 1.5 * pct
      const x1 = cx + r * Math.cos(startAngle), y1 = cy + r * Math.sin(startAngle)
      const x2 = cx + r * Math.cos(endAngle), y2 = cy + r * Math.sin(endAngle)
      const large = pct > 0.5 ? 1 : 0
      const col = score < 40 ? '#da1e28' : score < 70 ? '#8a6d00' : '#198038'
      arc.setAttribute('d', `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`)
      arc.setAttribute('stroke', col)
    })
  }
}

// ChaosCanvas: a data-driven entropy timeline. It is deliberately still until
// Astartis emits a real packet/entropy frame; animation is only interpolation
// between measured windows, never a decorative security visual.
Hooks.ChaosCanvas = {
  mounted() {
    const canvas = this.el
    const ctx = canvas.getContext('2d')
    const prefersReducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    const threshold = 7.2
    this.frames = []
    this.current = []
    this.target = []
    this.pendingDraw = null

    const resize = () => {
      const scale = window.devicePixelRatio || 1
      const cssWidth = canvas.offsetWidth || 400
      const cssHeight = canvas.offsetHeight || 200
      canvas.width = Math.floor(cssWidth * scale)
      canvas.height = Math.floor(cssHeight * scale)
      ctx.setTransform(scale, 0, 0, scale, 0, 0)
      this.width = cssWidth
      this.height = cssHeight
      this.draw(true)
    }

    const pointAt = (values, index, left, top, plotWidth, plotHeight) => {
      const count = Math.max(values.length - 1, 1)
      const entropy = Math.max(0, Math.min(8, values[index] || 0))
      return {
        x: left + (index / count) * plotWidth,
        y: top + (1 - entropy / 8) * plotHeight
      }
    }

    this.draw = (instant = false) => {
      if (!this.width || !this.height) return
      const w = this.width
      const h = this.height
      const left = 34
      const right = 14
      const top = 18
      const bottom = 28
      const plotWidth = Math.max(1, w - left - right)
      const plotHeight = Math.max(1, h - top - bottom)
      const hasData = this.current.length > 0

      ctx.clearRect(0, 0, w, h)
      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, w, h)

      // Quiet grid and fixed mathematical scale.
      ctx.font = '10px IBM Plex Mono, Consolas, monospace'
      ctx.textBaseline = 'middle'
      for (let value = 0; value <= 8; value += 2) {
        const y = top + (1 - value / 8) * plotHeight
        ctx.strokeStyle = '#e0e0e0'
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.moveTo(left, y)
        ctx.lineTo(left + plotWidth, y)
        ctx.stroke()
        ctx.fillStyle = '#6f6f6f'
        ctx.fillText(String(value), 7, y)
      }

      const thresholdY = top + (1 - threshold / 8) * plotHeight
      ctx.setLineDash([4, 4])
      ctx.strokeStyle = '#da1e28'
      ctx.beginPath()
      ctx.moveTo(left, thresholdY)
      ctx.lineTo(left + plotWidth, thresholdY)
      ctx.stroke()
      ctx.setLineDash([])
      ctx.fillStyle = '#a2191f'
      ctx.fillText('anomaly 7.2', Math.max(left + 4, w - 88), thresholdY - 8)

      if (!hasData) {
        ctx.fillStyle = '#525252'
        ctx.font = '12px IBM Plex Sans, Arial, sans-serif'
        ctx.fillText('Waiting for Astartis entropy windows', left + 12, top + plotHeight / 2)
        return
      }

      const values = this.current
      const gradient = ctx.createLinearGradient(0, top, 0, top + plotHeight)
      gradient.addColorStop(0, 'rgba(218, 30, 40, 0.16)')
      gradient.addColorStop(0.55, 'rgba(241, 194, 27, 0.10)')
      gradient.addColorStop(1, 'rgba(36, 161, 72, 0.05)')

      ctx.beginPath()
      values.forEach((_, i) => {
        const p = pointAt(values, i, left, top, plotWidth, plotHeight)
        if (i === 0) ctx.moveTo(p.x, p.y)
        else ctx.lineTo(p.x, p.y)
      })
      const last = pointAt(values, values.length - 1, left, top, plotWidth, plotHeight)
      ctx.lineTo(last.x, top + plotHeight)
      ctx.lineTo(left, top + plotHeight)
      ctx.closePath()
      ctx.fillStyle = gradient
      ctx.fill()

      ctx.beginPath()
      values.forEach((_, i) => {
        const p = pointAt(values, i, left, top, plotWidth, plotHeight)
        if (i === 0) ctx.moveTo(p.x, p.y)
        else ctx.lineTo(p.x, p.y)
      })
      const lineColor = values[values.length - 1] >= threshold ? '#da1e28' : '#0f62fe'
      ctx.strokeStyle = lineColor
      ctx.lineWidth = 2
      ctx.stroke()

      ctx.beginPath()
      ctx.arc(last.x, last.y, 4, 0, Math.PI * 2)
      ctx.fillStyle = lineColor
      ctx.fill()
      ctx.strokeStyle = '#ffffff'
      ctx.lineWidth = 2
      ctx.stroke()

      ctx.fillStyle = '#525252'
      ctx.font = '10px IBM Plex Mono, Consolas, monospace'
      ctx.fillText('entropy bits', left, h - 10)
      ctx.fillStyle = lineColor
      ctx.fillText(`${values[values.length - 1].toFixed(2)} H`, Math.max(left, last.x - 24), Math.max(10, last.y - 12))

      if (!instant && !prefersReducedMotion && this.target.length) {
        const delta = this.target.reduce((sum, value, i) => sum + Math.abs(value - (this.current[i] ?? value)), 0)
        if (delta > 0.01) {
          this.current = this.target.map((value, i) => (this.current[i] ?? value) + (value - (this.current[i] ?? value)) * 0.24)
          this.pendingDraw = requestAnimationFrame(() => this.draw())
        }
      }
    }

    this.handleEvent('packet_frame', ({entropy}) => {
      const measured = Number(entropy)
      if (!Number.isFinite(measured)) return
      this.frames.push(Math.max(0, Math.min(8, measured)))
      if (this.frames.length > 50) this.frames.shift()
      this.target = [...this.frames]
      if (!this.current.length || prefersReducedMotion) this.current = [...this.frames]
      this.draw(prefersReducedMotion)
    })

    this.resizeObserver = new ResizeObserver(resize)
    this.resizeObserver.observe(canvas)
    resize()
  },
  destroyed() {
    if (this.resizeObserver) this.resizeObserver.disconnect()
    if (this.pendingDraw) cancelAnimationFrame(this.pendingDraw)
  }
}

// TermInput: handle terminal command input
Hooks.TermInput = {
  mounted() {
    this.el.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        const val = this.el.value.trim()
        if (val) { this.pushEvent('terminal_cmd', {cmd: val}); this.el.value = '' }
      }
    })
  }
}

// KeyboardShortcuts
document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 't') {
    e.preventDefault()
    document.querySelector('#terminal-input')?.focus()
  }
  // Ctrl+1..9 → switch dock app
  if (e.ctrlKey && e.key >= '1' && e.key <= '9') {
    const apps = ['network','defense','agents','sandbox','pipeline','nac','reports','audit','settings']
    const idx = parseInt(e.key) - 1
    if (apps[idx]) window.liveSocket?.main?.pushEvent?.('switch_app', {app: apps[idx]})
  }
  if (e.key === 'F11') {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen?.()
    else document.exitFullscreen?.()
  }
})

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

let liveSocket

try {
  liveSocket = new LiveSocket("/live", Socket, {
    longPollFallbackMs: 2500,
    params: {_csrf_token: csrfToken},
    hooks: {...colocatedHooks, ...Hooks},
  })

  topbar.config({barColors: {0: "#4589ff"}, shadowColor: "rgba(0, 0, 0, .3)"})
  window.addEventListener("phx:page-loading-start", _info => topbar.show(300))
  window.addEventListener("phx:page-loading-stop", _info => topbar.hide())
  liveSocket.connect()
  window.liveSocket = liveSocket
} catch (error) {
  window.__astartisBootError = {message: error?.message || String(error), stack: error?.stack || ""}
  console.error("Astartis LiveView boot failed", window.__astartisBootError)
}

if (process.env.NODE_ENV === "development") {
  window.addEventListener("phx:live_reload:attached", ({detail: reloader}) => {
    reloader.enableServerLogs()
    let keyDown
    window.addEventListener("keydown", e => keyDown = e.key)
    window.addEventListener("keyup", _e => keyDown = null)
    window.addEventListener("click", e => {
      if(keyDown === "c"){ e.preventDefault(); e.stopImmediatePropagation(); reloader.openEditorAtCaller(e.target) }
      else if(keyDown === "d"){ e.preventDefault(); e.stopImmediatePropagation(); reloader.openEditorAtDef(e.target) }
    }, true)
    window.liveReloader = reloader
  })
}
