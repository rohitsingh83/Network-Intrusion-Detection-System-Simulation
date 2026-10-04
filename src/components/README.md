# Dashboard components

Reusable visual components are implemented as small render functions in `../main.js` to keep this no-framework student console easy to inspect: metric cards, charts, filter bars, severity/status chips, flow tables, and the investigation detail panel. Chart markup is inline SVG generated only from numeric data; text values are escaped through `../services/api.js` before insertion.
