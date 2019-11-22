# psfrag
A utility for code fragments in the Pokemon Stadium games.

For Linux and Windows.

# usage
```
psfrag <cmd>

Commands:
	scan <rom>
		show fragments within a rom
	depends <rom> <fragnum>
		show what fragments this one depends on
	extract <rom> <fragnum>
		extract one fragment
	extract-all <rom>
		extract all fragments
	mkdb <rom> <sqlite3 database>
		populate an SQLite3 database with fragment data
```
