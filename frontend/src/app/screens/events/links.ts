import { paths } from '../../routes'

/** Open one attempt's detail sheet in the Authentication log. */
export const eventPath = (tid: string, eventId: string) => paths.events(tid, { event: eventId })
