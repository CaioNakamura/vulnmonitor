const canvas = document.getElementById("grafico");


if (canvas) {

    new Chart(canvas, {

        type: "doughnut",

        data: {

            labels: [

                "Baixa",
                "Média",
                "Alta",
                "Crítica"

            ],

            datasets: [{

                data: [

                    {{ total_baixas | default(0) }},

                    {{ total_medias | default(0) }},

                    {{ total_altas | default(0) }},

                    {{ total_criticas | default(0) }}

                ],

                backgroundColor: [

                    "#22C55E",
                    "#EAB308",
                    "#F97316",
                    "#DC2626"

                ],

                borderWidth: 0

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: true,

            plugins: {

                legend: {

                    position: "bottom"

                }

            }

        }

    });

}