// Thin d3 helpers: concepts own all visual rendering; these only compute geometry.
import { scaleBand, scaleLinear, scaleTime } from 'd3-scale'
import { area, line, curveMonotoneX } from 'd3-shape'
import { max } from 'd3-array'

export interface HourPoint { hourEnd: Date; accept: number; reject: number }

export function hourlyGeometry(points: HourPoint[], width: number, height: number, pad = { top: 8, right: 8, bottom: 20, left: 28 }) {
  const x = scaleTime().domain([points[0].hourEnd, points[points.length - 1].hourEnd]).range([pad.left, width - pad.right])
  const y = scaleLinear().domain([0, Math.max(1, max(points, (p) => p.accept + p.reject) ?? 1)]).nice(4).range([height - pad.bottom, pad.top])
  const acceptArea = area<HourPoint>().x((p) => x(p.hourEnd)).y0(y(0)).y1((p) => y(p.accept)).curve(curveMonotoneX)(points) ?? ''
  const acceptLine = line<HourPoint>().x((p) => x(p.hourEnd)).y((p) => y(p.accept)).curve(curveMonotoneX)(points) ?? ''
  const rejectLine = line<HourPoint>().x((p) => x(p.hourEnd)).y((p) => y(p.reject)).curve(curveMonotoneX)(points) ?? ''
  const band = scaleBand<number>().domain(points.map((_, i) => i)).range([pad.left, width - pad.right]).padding(0.25)
  return { x, y, band, acceptArea, acceptLine, rejectLine, yTicks: y.ticks(4), pad }
}

export function barScale(maxValue: number, length: number) {
  return scaleLinear().domain([0, Math.max(1, maxValue)]).range([0, length])
}
