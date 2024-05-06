# DataTable HTML Template
datatable_template = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DataTables Column Filter Example</title>
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css">
<script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.js"></script>
<script type="text/javascript" src="https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>
<script>
$(document).ready(function() {{
    // Initialize DataTable
    var table = $('#dataTable').DataTable({{
        orderCellsTop: true,  // Ensure that the sorting will use the top row
        initComplete: function() {{
            var api = this.api();

            // Create and append the second row for column filters
            var filterRow = $('<tr>').appendTo(api.table().header());

            api.columns().indexes().flatten().each(function(i) {{
                var column = api.column(i);
                var title = $(column.header()).text(); // Get the text of the original header

                var select = $('<select><option value=""></option></select>')
                    .appendTo($('<th>').appendTo(filterRow))
                    .on('change', function() {{
                        var val = $.fn.dataTable.util.escapeRegex($(this).val());
                        column.search(val ? '^' + val + '$' : '', true, false).draw();
                    }});

                column.data().unique().sort().each(function(d) {{
                    select.append($('<option>', {{
                        value: d,
                        text: d
                    }}));
                }});
            }});
        }}
    }});
}});
</script>
</head>
<body>
{0}
</body>
</html>
"""