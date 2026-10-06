// Package icon рисует эмблему AnyRoute кодом (поле расстояний +
// суперсэмплинг): неоновое кольцо и «маршрут» из трёх узлов. Из одного
// рисунка получаются иконка exe, установщика и значки трея по состояниям.
package icon

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Цвета состояний.
var (
	Cyan  = color.RGBA{0x22, 0xd3, 0xee, 0xff}
	Amber = color.RGBA{0xf5, 0x9e, 0x0b, 0xff}
	Grey  = color.RGBA{0x8a, 0xa0, 0xb8, 0xff}
	Red   = color.RGBA{0xf4, 0x3f, 0x5e, 0xff}
)

type seg struct{ ax, ay, bx, by float64 }

func distSeg(px, py float64, s seg) float64 {
	dx, dy := s.bx-s.ax, s.by-s.ay
	t := ((px-s.ax)*dx + (py-s.ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	x, y := s.ax+t*dx, s.ay+t*dy
	return math.Hypot(px-x, py-y)
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }

// Render рисует эмблему size×size. withBG — тёмная скруглённая подложка
// (для exe); без неё — прозрачный фон (трей).
func Render(size int, accent color.RGBA, withBG bool) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	const ss = 4 // суперсэмплинг
	route := []seg{
		{0.30, 0.67, 0.50, 0.33},
		{0.50, 0.33, 0.70, 0.67},
	}
	nodes := [][2]float64{{0.30, 0.67}, {0.50, 0.33}, {0.70, 0.67}}
	ringR, ringW, lineW, nodeR := 0.40, 0.065, 0.075, 0.085
	if size <= 24 { // мелкий значок — толще линии
		ringW, lineW, nodeR = 0.09, 0.10, 0.11
	}
	if withBG { // поля внутри подложки
		ringR = 0.34
		route = []seg{{0.34, 0.63, 0.50, 0.36}, {0.50, 0.36, 0.66, 0.63}}
		nodes = [][2]float64{{0.34, 0.63}, {0.50, 0.36}, {0.66, 0.63}}
	}
	ar, ag, ab := float64(accent.R), float64(accent.G), float64(accent.B)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/ss) / float64(size)
					cr, cg, cb, ca := 0.0, 0.0, 0.0, 0.0
					inBG := false
					if withBG {
						// скруглённый квадрат 0.06..0.94, радиус 0.2
						qx := math.Max(math.Abs(px-0.5)-0.24, 0)
						qy := math.Max(math.Abs(py-0.5)-0.24, 0)
						if math.Hypot(qx, qy) <= 0.20 {
							inBG = true
							t := py
							cr, cg, cb, ca = 10+8*t, 16+10*t, 30+16*t, 255
						}
					}
					// поле расстояний до фигуры
					d := math.Abs(math.Hypot(px-0.5, py-0.5)-ringR) - ringW/2
					for _, s := range route {
						d = math.Min(d, distSeg(px, py, s)-lineW/2)
					}
					for _, n := range nodes {
						d = math.Min(d, math.Hypot(px-n[0], py-n[1])-nodeR/2)
					}
					shape := clamp01(-d * float64(size) * 1.5)
					glow := 0.0
					if (withBG && inBG) || (!withBG && size > 24) {
						glow = 0.55 * math.Exp(-math.Max(d, 0)*28)
					}
					sa := math.Max(shape, glow*(1-shape)) // неон: ядро + свечение
					// ядро светлее акцента
					lr := ar + (255-ar)*0.35*shape
					lg := ag + (255-ag)*0.35*shape
					lb := ab + (255-ab)*0.35*shape
					// смешивание поверх подложки
					oa := sa*255 + ca*(1-sa)
					if oa > 0 {
						cr = (lr*sa*255 + cr*ca*(1-sa)) / oa
						cg = (lg*sa*255 + cg*ca*(1-sa)) / oa
						cb = (lb*sa*255 + cb*ca*(1-sa)) / oa
					}
					ca = oa
					r += cr * ca
					g += cg * ca
					b += cb * ca
					a += ca
				}
			}
			n := float64(ss * ss)
			if a > 0 {
				img.SetRGBA(x, y, color.RGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(a / n)})
			}
		}
	}
	return img
}

// PNG кодирует изображение в PNG.
func PNG(img image.Image) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// ICO собирает .ico из PNG-кадров (поддерживается начиная с Windows Vista).
func ICO(images ...*image.RGBA) []byte {
	var pngs [][]byte
	for _, im := range images {
		pngs = append(pngs, PNG(im))
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, [3]uint16{0, 1, uint16(len(images))})
	offset := 6 + 16*len(images)
	for i, im := range images {
		w := im.Bounds().Dx()
		dim := byte(w)
		if w >= 256 {
			dim = 0
		}
		buf.Write([]byte{dim, dim, 0, 0})
		_ = binary.Write(&buf, binary.LittleEndian, uint16(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint16(32))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(pngs[i])))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(offset))
		offset += len(pngs[i])
	}
	for _, p := range pngs {
		buf.Write(p)
	}
	return buf.Bytes()
}

// Tray — значок трея для состояния.
func Tray(accent color.RGBA) []byte {
	return ICO(Render(16, accent, false), Render(20, accent, false), Render(24, accent, false), Render(32, accent, false))
}

// App — иконка приложения (exe, установщик): 16…256 с подложкой.
func App() []byte {
	var frames []*image.RGBA
	for _, s := range []int{16, 24, 32, 48, 64, 128, 256} {
		frames = append(frames, Render(s, Cyan, true))
	}
	return ICO(frames...)
}
