# Badges

The myTeamSpeak badge artwork, one SVG per badge UUID.

`tools/fetch-badges.py` regenerates this directory from the same source the
official client uses:

- index: `https://badges-content.teamspeak.com/list` (a protobuf list of
  `uuid` / name / url)
- artwork: that url with `.svg` appended

Nothing here is invented or redrawn. The badge art belongs to TeamSpeak /
myTeamSpeak; it is checked in so a client can show a member's badges offline
instead of hotlinking their CDN. `tools/badges.py` converts each SVG into an
Android VectorDrawable at build time and names the resource after the UUID, so
the shell looks a badge up by the id it already has.

Not every badge is expressible as a VectorDrawable — a rotated transform, an
`objectBoundingBox` gradient or a `fill:none` stroke is refused by
`svg2vector.py` and reported at build time. Those badges simply have no picture
until the converter learns the shape; the row still shows the others.
