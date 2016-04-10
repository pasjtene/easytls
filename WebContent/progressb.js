/**
 * 
 */

function progressBar(percent) {
	var p = percent;
			document.getElementById("myBar").style.width = percent + '%';
			document.getElementById("label").innerHTML = percent +'%';
						
}


function progressPercent(percent) {
	var p = percent;
		document.getElementById("progress").innerHTML = percent +'%';
					
}