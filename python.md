# Misc
## Extract Digit from String
```python
''.join(filter(str.isdigit, 'asdf234sdf'))
```

# Date & Time
## Create Datetime from String
```python
dt.strptime('2019-12-01', '%Y-%m-%d')
```

# int to hex
```python
format(24604052029401386049980296953784287079059245867880966944246662849341507003750, 'x')
```

# decode hex
```python
bytes.fromhex('3665666331613564626238393034373531636536353636613330356262386566').decode('utf-8')
```


# Pandas
```python
import pandas as pd
```
## Read/Create Dataframe
```python
df = pd.read_csv(data.csv, names=['column1', 'column2'])
```

## Describe Data
```python
data.head()
data.tail()
data.describe()
data.columns
data.shape
```

## Simple Plot
```python
df['price'].plot()
```

## Calculate EMA
```python
df['price'].ewm(span=10, adjust=False).mean()
```


# Plotly Express
```python
import plotly.express as px
```
## Plot Time Series (Lines)
```python
fig2 = px.line(plot_data,x="date", y="close")
fig2.add_trace(go.Scatter(
    x=plot_data['date'],
    y=plot_data['EMA200'],
    name='EMA200'
))
fig2.add_trace(go.Scatter(
    x=plot_data['date'],
    y=plot_data['EMA600'],
    name='EMA600'
))

fig.update_layout(
    xaxis_type="category"
)

fig2.show()
```
```python
fig3 = px.line(deltas, x=range(0,len(deltas)), y=deltas)
```

## Plot OHLC as Candlesticks with EMA's
```python
plot_data = data.tail(n=4000)
fig = go.Figure(data=[go.Candlestick(x=plot_data["date"],
                open=plot_data["open"],high=plot_data["high"],
                low=plot_data["low"],close=plot_data["close"])])

fig.add_scatter(x=plot_data['date'], y=plot_data['EMA100'], mode='lines', name="EMA100")
fig.add_scatter(x=plot_data['date'], y=plot_data['EMA200'], mode='lines', name="EMA200")

fig.update_layout(
    autosize=False,
    width=1000,
    height=1000,
    margin=dict(l=20, r=20, t=20, b=20),
    xaxis_type="category"
)

fig.show()
```
